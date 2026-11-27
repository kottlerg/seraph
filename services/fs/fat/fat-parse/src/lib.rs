// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/fat-parse/src/lib.rs

//! Pure FAT on-disk structure decoders.
//!
//! Decodes the BIOS Parameter Block geometry and FAT directory entries
//! (8.3 short names, long-file-name runs, case-insensitive matching) from raw
//! sector bytes, locates every slot an entry occupies for its removal
//! ([`RemoveRunScan`]), finds a run of free slots for a new entry
//! ([`FreeRunScan`]), bounds cluster numbers to the data region
//! ([`is_data_cluster`]), locates, reads and writes FAT entries
//! ([`fat_entry_location`], [`read_fat_entry`], [`write_fat_entry`]),
//! places a file offset in its cluster chain ([`file_position`]), walks a
//! file write's sectors and gathers them into runs of contiguous sectors
//! ([`file_write::write_range`], through the driver's I/O), resumes a
//! sequential reader's chain walk ([`walk_start`]) and sizes its cache fills
//! ([`run_cluster_bound`], [`contiguous_clusters`], [`file_end_sector`],
//! [`run_pages`]), encodes
//! long names ([`encode_lfn`]) and packs their slots ([`pack_lfn_slot`]), picks
//! short-name numeric tails ([`TailSet`]), and keeps the node table's
//! recycling identifiers ([`node_slab::NodeSlab`]), the session pool
//! ([`session_pool::SessionPool`]) with the schedule of its sweeps for
//! sessions whose client is gone ([`sweep::SweepSchedule`]), and picks the
//! page cache's eviction victim ([`lru_victim`]) and the idle pages it keeps
//! when it gives the others back ([`keep_most_recent`]), and its index from a
//! cached page to its slot ([`page_index::PageIndex`]). This crate
//! performs no
//! I/O and holds no filesystem state: the `fatfs` service reads sectors over
//! a block-device IPC, hands the bytes here, and keeps the
//! geometry/cache/mutation engine on its side.
//! Keeping the parse of untrusted on-disk structures pure and host-testable is
//! the point — see
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use core::num::{NonZeroU8, NonZeroU32, NonZeroU64};

pub mod file_write;
pub mod node_slab;
pub mod page_index;
#[cfg(any(test, kani, fuzzing))]
pub mod property;
pub mod session_pool;
pub mod sweep;

// ── BIOS Parameter Block ────────────────────────────────────────────────────

/// Largest FAT sector size, in bytes: the Microsoft FAT specification permits
/// 512, 1024, 2048, and 4096. A hardware-specification bound, and the length
/// of every sector buffer the `fatfs` service keeps; the volume's own size
/// is `BPB_BytsPerSec`.
pub const MAX_SECTOR_SIZE: usize = 4096;

/// Smallest FAT sector size, in bytes; the BPB's boot signature at bytes
/// 510/511 lies inside it.
pub const MIN_SECTOR_SIZE: usize = 512;

// ── Page-cache bounds ──────────────────────────────────────────────────────

/// Fewest cache slots a `fatfs` page cache may grow to, each one page: its
/// ceiling on a machine of up to [`SLOT_RAM_DIVISOR`] × 256 pages (512 MiB) of
/// RAM. Above that the ceiling grows with RAM ([`slot_ceiling`]). The cache
/// takes a slot's page from memmgr when a miss needs the slot, and gives idle
/// pages back under memory pressure, so a mount pays only for the slots it
/// fills. Defined here, in the host-tested library, so
/// the svctest harness that checks the cache's bounds reads the same values
/// the driver uses.
pub const SLOT_COUNT: usize = 256;

/// Pages of system RAM per cache slot above [`SLOT_COUNT`]: a cache grows to
/// at most 1/512 of RAM.
pub const SLOT_RAM_DIVISOR: u64 = 512;

/// The slot ceiling of a `fatfs` page cache on a machine of
/// `system_ram_pages` pages of RAM: one slot per [`SLOT_RAM_DIVISOR`] pages,
/// and never fewer than [`SLOT_COUNT`].
#[must_use]
pub fn slot_ceiling(system_ram_pages: u64) -> usize
{
    usize::try_from(system_ram_pages / SLOT_RAM_DIVISOR)
        .unwrap_or(usize::MAX)
        .max(SLOT_COUNT)
}

/// Most pages the `fatfs` cache holds beyond its slot ceiling: it requests a
/// replacement page from memmgr only while its quarantined pages (still
/// mapped by a client) and clean spares number fewer than this. Shared with
/// svctest as [`slot_ceiling`] is.
pub const QUARANTINE_MAX: usize = 32;

/// One `fatfs` cache slot as [`lru_victim`] sees it.
#[derive(Clone, Copy, Debug)]
pub struct VictimView
{
    /// A reference holds the slot: a read or write is inside its page.
    pub referenced: bool,
    /// The slot holds a page cap to refill. One without holds no page: it
    /// gave its page back to memmgr, a page swap lost it, or a failed fill
    /// lost its cap.
    pub has_cap: bool,
    /// The caller excludes the slot: the pick in progress has passed over it
    /// already, or a client may still map its page.
    pub skipped: bool,
    /// The slot's last-use sequence number; lower is older.
    pub lru_seq: u64,
}

/// The index of the slot a `fatfs` cache refills on a miss it cannot meet
/// by growing: the least recently used one (the lowest `lru_seq`, the first
/// of a tie) that no reference holds, that holds a page cap, and that the
/// pick has not skipped. `None` when no slot qualifies.
#[must_use]
pub fn lru_victim(slots: impl IntoIterator<Item = VictimView>) -> Option<usize>
{
    let mut best: Option<(usize, u64)> = None;
    for (i, slot) in slots.into_iter().enumerate()
    {
        if slot.referenced || !slot.has_cap || slot.skipped
        {
            continue;
        }
        if best.is_none_or(|(_, seq)| slot.lru_seq < seq)
        {
            best = Some((i, slot.lru_seq));
        }
    }
    best.map(|(i, _)| i)
}

/// Idle pages a `fatfs` cache keeps when it gives its idle pages back under
/// memory pressure: the most recently used ones ([`keep_most_recent`]). A
/// request holds at most two slot references at a time (a run write over two
/// cache pages), so two kept pages let a miss evict when memmgr refuses the
/// cache a page at `Critical`; four keep the FAT, directory and data pages
/// one request walks. Shared with svctest as
/// [`slot_ceiling`] is.
pub const RELEASE_KEEP: usize = 4;

/// Mark in `kept` the `keep` most recently used slots (the highest
/// `lru_seq`, the first of a tie) that no reference holds, that hold a page
/// cap, and that the caller does not skip, or every such slot when there are
/// fewer: the idle pages a `fatfs` cache keeps when it gives the others back.
/// `kept` holds a mark per slot and is cleared first; a slot past its length
/// is never marked.
pub fn keep_most_recent(
    slots: &(impl IntoIterator<Item = VictimView> + Clone),
    keep: usize,
    kept: &mut [bool],
)
{
    kept.fill(false);
    for _ in 0..keep
    {
        let mut best: Option<(usize, u64)> = None;
        for (i, slot) in slots.clone().into_iter().enumerate()
        {
            let eligible = !slot.referenced
                && slot.has_cap
                && !slot.skipped
                && kept.get(i).is_some_and(|&mark| !mark);
            if eligible && best.is_none_or(|(_, seq)| slot.lru_seq > seq)
            {
                best = Some((i, slot.lru_seq));
            }
        }
        let Some((i, _)) = best
        else
        {
            return;
        };
        if let Some(mark) = kept.get_mut(i)
        {
            *mark = true;
        }
    }
}

/// FAT variant detected from cluster count.
#[derive(Clone, Copy)]
pub enum FatType
{
    Fat16,
    Fat32,
}

/// Failure modes of [`parse_bpb_geometry`].
pub enum BpbError
{
    /// Boot signature (bytes 510/511) is not `0x55 0xAA`.
    BadSignature,
    /// `bytes_per_sector` or `sectors_per_cluster` is zero; either would
    /// divide-by-zero in the geometry computation.
    ZeroDivisor,
    /// `bytes_per_sector` is not the device's logical block size, or not a
    /// size the FAT specification permits (a power of two from
    /// [`MIN_SECTOR_SIZE`] to [`MAX_SECTOR_SIZE`]). The `fatfs` page cache,
    /// FAT walker, and directory code address one device block per sector,
    /// so a volume whose sectors are not the device's blocks is refused
    /// rather than read with mismatched offsets.
    UnsupportedSectorSize,
    /// The geometry is inconsistent: the volume has no FAT copy or no
    /// reserved sector (the FAT would overlay the boot sector), its
    /// `sectors_per_cluster` is not one the FAT specification permits (a
    /// power of two up to 128), the data
    /// region's start overflows a 32-bit sector number, the volume has
    /// more clusters than its FAT has entries for (or than FAT32's largest
    /// cluster number allows), so a cluster in the data region would have
    /// no FAT entry, or one past the FAT, a FAT32 root cluster lies
    /// outside the data region, or the volume declares more sectors than
    /// its partition holds, so its data region would reach past the
    /// partition's end.
    BadGeometry,
    /// The volume has fewer than [`FAT16_MIN_CLUSTERS`] clusters, which
    /// makes it FAT12 under the Microsoft specification's type rule. Its
    /// FAT holds 12-bit entries, and the `fatfs` FAT walker and allocator
    /// read and write only 16- and 32-bit ones.
    Fat12,
}

/// Fewest clusters a FAT16 volume has: the Microsoft specification types a
/// volume with fewer as FAT12.
pub const FAT16_MIN_CLUSTERS: u32 = 4085;

/// Geometry decoded from a FAT BPB (sector 0).
///
/// Mirrors the fields the `fatfs` service copies into its `FatState`. The
/// service owns the cached-FAT-sector and advisory-hint state; this struct
/// carries only what the pure decode produces. `fsinfo_sector` is `Some` only
/// for a FAT32 volume whose `FSInfo` field names a sector inside the reserved
/// region (not the `0`/`0xFFFF` "absent" markers), so the caller assigns it
/// conditionally and otherwise keeps its `u32::MAX` sentinel.
pub struct BpbGeometry
{
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub root_entry_count: u16,
    pub fat_size: u32,
    /// The FAT32 root directory's first cluster (BPB offset 44). 0 on
    /// FAT16, whose root is the fixed area before the data region and
    /// whose bytes at offset 44 belong to the volume label (`BS_VolLab`).
    pub root_cluster: u32,
    pub data_start_sector: u32,
    /// The volume's sector count (`BPB_TotSec16`, or `BPB_TotSec32` when
    /// that is 0).
    pub total_sectors: u32,
    pub total_clusters: u32,
    pub fat_type: FatType,
    pub fsinfo_sector: Option<u32>,
}

/// Decode and validate the BIOS Parameter Block from sector 0, read from a
/// device whose logical block size is `device_block_size` bytes and which
/// holds `partition_sectors` of those blocks.
///
/// Validates the boot signature, the sector size, and the geometry (every
/// check is listed under `# Errors`), computing on the way the data-region
/// start, total cluster count, FAT variant (per the Microsoft FAT32
/// specification's type rule: under 4085 clusters FAT12, under 65525
/// FAT16, else FAT32), and — for FAT32 — the `FSInfo` sector,
/// which is `None` unless it names a sector inside the reserved region.
///
/// # Errors
/// Returns [`BpbError::BadSignature`] when bytes 510/511 are not `0x55 0xAA`,
/// [`BpbError::ZeroDivisor`] when `bytes_per_sector` or
/// `sectors_per_cluster` is zero, [`BpbError::UnsupportedSectorSize`]
/// when `bytes_per_sector` is non-zero but not `device_block_size` or not a
/// FAT sector size, or when `sector_data` is shorter than
/// [`MIN_SECTOR_SIZE`],
/// [`BpbError::Fat12`] for a FAT12 cluster count, or
/// [`BpbError::BadGeometry`] when `num_fats` or `reserved_sectors` is zero,
/// `sectors_per_cluster` is not a power of two, the data region's start
/// overflows, the FAT cannot hold an entry for
/// every cluster, a FAT32 root cluster lies outside the data region, or the
/// volume's sector count exceeds `partition_sectors`.
pub fn parse_bpb_geometry(
    sector_data: &[u8],
    device_block_size: u32,
    partition_sectors: u64,
) -> Result<BpbGeometry, BpbError>
{
    let Some(head) = sector_data.first_chunk::<MIN_SECTOR_SIZE>()
    else
    {
        return Err(BpbError::UnsupportedSectorSize);
    };
    let geometry = decode_bpb(head)?;
    if u32::from(geometry.bytes_per_sector) != device_block_size
    {
        return Err(BpbError::UnsupportedSectorSize);
    }
    // Every bound the driver derives from the cluster count (the data
    // region, the allocator's scan, a chain walk's length) must follow the
    // disk, not the number the BPB declares.
    if u64::from(geometry.total_sectors) > partition_sectors
    {
        return Err(BpbError::BadGeometry);
    }
    Ok(geometry)
}

/// [`parse_bpb_geometry`] without the device-block check: decode and
/// validate the BPB in the first [`MIN_SECTOR_SIZE`] bytes of sector 0, which
/// hold every BPB field and the boot signature whatever the sector size.
fn decode_bpb(sector_data: &[u8; MIN_SECTOR_SIZE]) -> Result<BpbGeometry, BpbError>
{
    // Validate boot signature.
    if sector_data[510] != 0x55 || sector_data[511] != 0xAA
    {
        return Err(BpbError::BadSignature);
    }

    let bytes_per_sector = u16::from_le_bytes([sector_data[11], sector_data[12]]);
    let sectors_per_cluster = sector_data[13];
    let reserved_sectors = u16::from_le_bytes([sector_data[14], sector_data[15]]);
    let num_fats = sector_data[16];
    let root_entry_count = u16::from_le_bytes([sector_data[17], sector_data[18]]);

    // Validate fields used as divisors to prevent division by zero.
    if sectors_per_cluster == 0 || bytes_per_sector == 0
    {
        return Err(BpbError::ZeroDivisor);
    }
    if !is_sector_size(usize::from(bytes_per_sector))
    {
        return Err(BpbError::UnsupportedSectorSize);
    }
    // The FAT starts after the reserved sectors, the boot sector among
    // them, and every FAT write goes to each of the num_fats copies.
    // The specification permits only a power of two sectors per cluster
    // (`BPB_SecPerClus`), so a cluster count is the data region's sectors
    // shifted down, with no division.
    if num_fats == 0 || reserved_sectors == 0 || !sectors_per_cluster.is_power_of_two()
    {
        return Err(BpbError::BadGeometry);
    }

    let total_sectors_16 = u16::from_le_bytes([sector_data[19], sector_data[20]]);
    let fat_size_16 = u16::from_le_bytes([sector_data[22], sector_data[23]]);
    let total_sectors_32 = u32::from_le_bytes([
        sector_data[32],
        sector_data[33],
        sector_data[34],
        sector_data[35],
    ]);

    // FAT32 extended BPB.
    let fat_size_32 = u32::from_le_bytes([
        sector_data[36],
        sector_data[37],
        sector_data[38],
        sector_data[39],
    ]);
    let root_cluster = u32::from_le_bytes([
        sector_data[44],
        sector_data[45],
        sector_data[46],
        sector_data[47],
    ]);

    let fat_size = if fat_size_16 != 0
    {
        u32::from(fat_size_16)
    }
    else
    {
        fat_size_32
    };

    let total_sectors = if total_sectors_16 != 0
    {
        u32::from(total_sectors_16)
    }
    else
    {
        total_sectors_32
    };

    // Root directory sectors (FAT16 only).
    // The sector size is a power of two, so the ceiling of the division is a
    // shift of the bytes rounded up; the bytes stay below 2^22.
    let root_dir_sectors = u32::from(root_entry_count)
        .wrapping_mul(32)
        .wrapping_add(u32::from(bytes_per_sector))
        .wrapping_sub(1)
        >> bytes_per_sector.trailing_zeros();

    let data_start_sector = u32::from(num_fats)
        .checked_mul(fat_size)
        .and_then(|fats| fats.checked_add(u32::from(reserved_sectors)))
        .and_then(|start| start.checked_add(root_dir_sectors))
        .ok_or(BpbError::BadGeometry)?;

    let data_sectors = total_sectors.saturating_sub(data_start_sector);
    let total_clusters = data_sectors >> sectors_per_cluster.trailing_zeros();

    // FAT type determination per the Microsoft specification. FAT12 is
    // refused: the driver reads only 16- and 32-bit FAT entries.
    if total_clusters < FAT16_MIN_CLUSTERS
    {
        return Err(BpbError::Fat12);
    }
    let (fat_type, fsinfo_sector) = if total_clusters < 65525
    {
        (FatType::Fat16, None)
    }
    else
    {
        (
            FatType::Fat32,
            named_fsinfo_sector(sector_data, reserved_sectors),
        )
    };

    check_fat_capacity(fat_type, fat_size, bytes_per_sector, total_clusters)?;
    let root_cluster = root_cluster_of(fat_type, root_cluster, total_clusters)?;

    Ok(BpbGeometry {
        bytes_per_sector,
        sectors_per_cluster,
        reserved_sectors,
        num_fats,
        root_entry_count,
        fat_size,
        root_cluster,
        data_start_sector,
        total_sectors,
        total_clusters,
        fat_type,
        fsinfo_sector,
    })
}

/// The root directory's first cluster for a volume of `fat_type` whose BPB
/// offset 44 holds `bpb_root`: `bpb_root` on FAT32, 0 on FAT16, where those
/// bytes belong to the volume label (`BS_VolLab`) and the root is the fixed
/// area before the data region.
///
/// # Errors
/// [`BpbError::BadGeometry`] when a FAT32 root cluster lies outside the data
/// region: the FAT32 root is an ordinary cluster chain, so its first cluster
/// must lie there like any other.
fn root_cluster_of(fat_type: FatType, bpb_root: u32, total_clusters: u32) -> Result<u32, BpbError>
{
    match fat_type
    {
        FatType::Fat16 => Ok(0),
        FatType::Fat32 if is_data_cluster(bpb_root, total_clusters) => Ok(bpb_root),
        FatType::Fat32 => Err(BpbError::BadGeometry),
    }
}

/// The FAT32 `FSInfo` sector a BPB names, or `None` when it names none.
///
/// The extended BPB holds the sector's LBA at offset 48 (2 bytes). A value
/// of 0 or 0xFFFF means "no `FSInfo` sector"; the caller holds the
/// `u32::MAX` sentinel in those cases so the allocator skips the load and
/// falls back to a full FAT scan. The `FSInfo` sector lives in the reserved
/// region; one named past it lies in a FAT copy or the data region, where
/// writing the hints back would corrupt the volume, so it is treated as
/// absent too.
fn named_fsinfo_sector(sector_data: &[u8; MIN_SECTOR_SIZE], reserved_sectors: u16) -> Option<u32>
{
    let fsinfo = u16::from_le_bytes([sector_data[48], sector_data[49]]);
    (fsinfo != 0 && fsinfo != 0xFFFF && fsinfo < reserved_sectors).then_some(u32::from(fsinfo))
}

/// Whether `size` is a FAT sector size: a power of two from
/// [`MIN_SECTOR_SIZE`] to [`MAX_SECTOR_SIZE`].
#[must_use]
pub fn is_sector_size(size: usize) -> bool
{
    size.is_power_of_two() && (MIN_SECTOR_SIZE..=MAX_SECTOR_SIZE).contains(&size)
}

/// Refuse a cluster count the FAT cannot describe.
///
/// Every data cluster `2..2 + total_clusters` needs a FAT entry inside one
/// FAT copy of `fat_size` sectors, and a FAT32 cluster number stops below
/// the `0x0FFF_FFF7` bad-cluster marker. Past either bound a cluster number
/// the driver accepts as in the data region would address a FAT entry past
/// the FAT, or overflow the entry-offset arithmetic.
fn check_fat_capacity(
    fat_type: FatType,
    fat_size: u32,
    bytes_per_sector: u16,
    total_clusters: u32,
) -> Result<(), BpbError>
{
    // A `u32` by `u16` product fits a `u64`, so this never saturates.
    let fat_bytes = u64::from(fat_size).saturating_mul(u64::from(bytes_per_sector));
    let (fat_entries, max_clusters) = match fat_type
    {
        FatType::Fat16 => (fat_bytes / 2, 0xFFF5u64),
        FatType::Fat32 => (fat_bytes / 4, 0x0FFF_FFF5u64),
    };
    // A `u32` count plus the two reserved entries fits a `u64`, so this
    // never saturates.
    let clusters = u64::from(total_clusters);
    if clusters.saturating_add(2) > fat_entries || clusters > max_clusters
    {
        return Err(BpbError::BadGeometry);
    }
    Ok(())
}

/// First sector of `cluster` within the data region.
///
/// Clusters 0 and 1 are reserved by the FAT spec (0 = free-marker,
/// 1 = reserved); valid data-region clusters start at 2. A reserved cluster
/// clamps to `data_start_sector` rather than underflowing `cluster - 2`, and
/// a cluster too large for the arithmetic saturates to `u32::MAX`, past
/// every partition bound, so the block driver refuses the access instead of
/// a wrapped LBA reaching another part of the volume. The I/O caller is
/// expected to filter clusters outside the data region ([`is_data_cluster`])
/// and log the hit; this function only avoids the overflow.
#[must_use]
pub fn cluster_to_sector(data_start_sector: u32, sectors_per_cluster: u8, cluster: u32) -> u32
{
    let Some(index) = cluster.checked_sub(2)
    else
    {
        return data_start_sector;
    };
    data_start_sector.saturating_add(index.saturating_mul(u32::from(sectors_per_cluster)))
}

/// Whether `cluster` names a cluster of the data region of a volume with
/// `total_clusters` data clusters: `2 <= cluster < 2 + total_clusters`.
///
/// A cluster number read from the FAT or a directory entry is untrusted
/// on-disk input; one outside this range is a corrupt chain or entry.
#[must_use]
pub fn is_data_cluster(cluster: u32, total_clusters: u32) -> bool
{
    cluster
        .checked_sub(2)
        .is_some_and(|index| index < total_clusters)
}

// ── FAT entries ─────────────────────────────────────────────────────────────

/// The bits of a FAT32 entry that hold a cluster number; the top four are
/// reserved (Microsoft FAT specification §4) and kept on a write.
const FAT32_ENTRY_MASK: u32 = 0x0FFF_FFFF;

impl FatType
{
    /// Bytes of one FAT entry.
    const fn entry_bytes(self) -> u32
    {
        match self
        {
            Self::Fat16 => 2,
            Self::Fat32 => 4,
        }
    }
}

/// Where the first FAT copy holds the entry of `cluster`: the sector, counted
/// from the volume start past `reserved_sectors`, and the entry's byte offset
/// in that sector of `bytes_per_sector` bytes.
///
/// `None` when `bytes_per_sector` is 0 or the sector number overflows, which
/// no cluster of the data region of a mounted volume reaches: the caller
/// bounds `cluster` to the data region ([`is_data_cluster`]) first.
#[must_use]
pub fn fat_entry_location(
    fat_type: FatType,
    reserved_sectors: u16,
    bytes_per_sector: u16,
    cluster: u32,
) -> Option<(u32, usize)>
{
    let bps = NonZeroU32::new(u32::from(bytes_per_sector))?;
    let offset = cluster.checked_mul(fat_type.entry_bytes())?;
    let sector = u32::from(reserved_sectors).checked_add(offset / bps)?;
    Some((sector, usize::try_from(offset % bps).ok()?))
}

/// The FAT entry at byte `offset` of the FAT sector `sector`: a FAT16 entry
/// widened, a FAT32 entry without its four reserved bits. `None` when the
/// entry does not lie inside `sector`.
#[must_use]
pub fn read_fat_entry(sector: &[u8], fat_type: FatType, offset: usize) -> Option<u32>
{
    let bytes = sector.get(offset..)?;
    match fat_type
    {
        FatType::Fat16 => bytes
            .first_chunk::<2>()
            .map(|&entry| u32::from(u16::from_le_bytes(entry))),
        FatType::Fat32 => bytes
            .first_chunk::<4>()
            .map(|&entry| u32::from_le_bytes(entry) & FAT32_ENTRY_MASK),
    }
}

/// Store `value` as the FAT entry at byte `offset` of the FAT sector
/// `sector`: the low 16 bits for FAT16, the low 28 bits for FAT32 with the
/// entry's four reserved bits kept. `None`, with `sector` unchanged, when the
/// entry does not lie inside `sector`.
pub fn write_fat_entry(
    sector: &mut [u8],
    fat_type: FatType,
    offset: usize,
    value: u32,
) -> Option<()>
{
    let bytes = sector.get_mut(offset..)?;
    match fat_type
    {
        FatType::Fat16 =>
        {
            let [low, high, ..] = value.to_le_bytes();
            *bytes.first_chunk_mut::<2>()? = [low, high];
        }
        FatType::Fat32 =>
        {
            let entry = bytes.first_chunk_mut::<4>()?;
            let reserved = u32::from_le_bytes(*entry) & !FAT32_ENTRY_MASK;
            *entry = (reserved | (value & FAT32_ENTRY_MASK)).to_le_bytes();
        }
    }
    Some(())
}

// ── File positions ──────────────────────────────────────────────────────────

/// Where a byte of a file lies in its cluster chain ([`file_position`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilePosition
{
    /// Clusters of the chain before the one holding the byte.
    pub cluster_index: u64,
    /// Bytes from the byte to the end of its cluster, at least 1.
    pub left_in_cluster: u64,
    /// The sector holding the byte, counted from its cluster's first.
    pub sector_in_cluster: u32,
    /// The byte's offset in that sector.
    pub offset_in_sector: usize,
    /// Bytes from the byte to the end of its sector, at least 1.
    pub left_in_sector: usize,
}

/// Where byte `offset` of a file lies, on a volume of `sectors_per_cluster`
/// sectors of `bytes_per_sector` bytes per cluster. `None` when either is 0,
/// which mount refuses ([`BpbError::ZeroDivisor`]).
#[must_use]
pub fn file_position(
    offset: u64,
    sectors_per_cluster: u8,
    bytes_per_sector: u16,
) -> Option<FilePosition>
{
    let bps = NonZeroU64::new(u64::from(bytes_per_sector))?;
    let cluster_bytes = bps.checked_mul(NonZeroU64::from(NonZeroU8::new(sectors_per_cluster)?))?;
    let offset_in_cluster = offset % cluster_bytes;
    let offset_in_sector = offset_in_cluster % bps;
    Some(FilePosition {
        cluster_index: offset / cluster_bytes,
        left_in_cluster: cluster_bytes.get().checked_sub(offset_in_cluster)?,
        sector_in_cluster: u32::try_from(offset_in_cluster / bps).ok()?,
        offset_in_sector: usize::try_from(offset_in_sector).ok()?,
        left_in_sector: usize::try_from(bps.get().checked_sub(offset_in_sector)?).ok()?,
    })
}

// ── Sequential reads ───────────────────────────────────────────────────────

/// Most pages one `fatfs` cache fill reads from the block device, in one
/// `BLK_READ_INTO_MEMORY`, when a memory-cap read misses on a sequential scan
/// of a file ([`run_pages`]). Each block request pays a fixed cost (the
/// device's DMA mapping and unmapping through devmgr, the interrupt, and the
/// IPC round trips) that a run pays once for all its pages; the pages past the
/// first are copied out of a run buffer of this many pages, which each mount
/// holds for its lifetime. A tuning bound: a longer scan takes more
/// fills.
pub const RUN_PAGES: u64 = 16;

/// Where one open of a file last stood in its cluster chain: the cluster at
/// `cluster_index` of the chain whose first cluster is `first_cluster`, as
/// read while the volume's chain epoch was `epoch`. A sequential reader's
/// next walk resumes here instead of at the chain's head ([`walk_start`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainCursor
{
    /// The volume's chain epoch when the cursor was taken: it moves whenever
    /// a chain is freed, after which a cluster the cursor names may belong to
    /// another chain or none.
    pub epoch: u64,
    /// The first cluster of the chain the cursor walked.
    pub first_cluster: u32,
    /// Clusters of the chain before [`Self::cluster`].
    pub cluster_index: u64,
    /// The cluster at [`Self::cluster_index`].
    pub cluster: u32,
}

/// Where a walk to cluster `target_index` of the chain starting at
/// `first_cluster` begins, as `(cluster_index, cluster)`: at `cursor` when
/// it was taken on that chain in the current `epoch` at or before the target,
/// else at the chain's head. A chain only grows at its end while its epoch
/// holds, so the links up to a cursor stay as the cursor read them.
#[must_use]
pub fn walk_start(
    cursor: Option<ChainCursor>,
    epoch: u64,
    first_cluster: u32,
    target_index: u64,
) -> (u64, u32)
{
    match cursor
    {
        Some(c)
            if c.epoch == epoch
                && c.first_cluster == first_cluster
                && c.cluster_index <= target_index =>
        {
            (c.cluster_index, c.cluster)
        }
        _ => (0, first_cluster),
    }
}

/// How many clusters of a chain, from `first` on, lie at consecutive cluster
/// numbers, so one device read covers them: at least 1 (`first` itself) and
/// at most `max` (1 when `max` is 0). `next` gives a cluster's successor in
/// the chain, `None` at its end or where it cannot be read, which ends the
/// run there.
#[must_use]
pub fn contiguous_clusters(first: u32, max: u32, mut next: impl FnMut(u32) -> Option<u32>) -> u32
{
    let mut count = 1;
    let mut cluster = first;
    while count < max
    {
        let Some(following) = cluster.checked_add(1)
        else
        {
            break;
        };
        if next(cluster) != Some(following)
        {
            break;
        }
        cluster = following;
        count = count.saturating_add(1);
    }
    count
}

/// Pages one cache fill reads for a run of sectors from `page_base` (a page's
/// first sector) to `run_end` (the sector past the run): the pages that cover
/// it, at least 1 and at most `max_pages` (1 when `max_pages` is 0), of
/// `sectors_per_page` sectors each.
#[must_use]
pub fn run_pages(page_base: u64, run_end: u64, sectors_per_page: NonZeroU64, max_pages: u64)
-> u64
{
    run_end
        .saturating_sub(page_base)
        .div_ceil(sectors_per_page.get())
        .clamp(1, max_pages.max(1))
}

/// The most clusters a run fill from a sector `sector_in_cluster` sectors
/// into its cluster can reach, for `sectors_per_cluster` sectors per
/// cluster: `max_pages` pages of `sectors_per_page` sectors past that sector
/// (a run starts at the sector's page, at or before it), counted from the
/// cluster's first sector. At least 1, and `u32::MAX` past that.
#[must_use]
pub fn run_cluster_bound(
    max_pages: u64,
    sectors_per_page: NonZeroU64,
    sector_in_cluster: u32,
    sectors_per_cluster: NonZeroU64,
) -> u32
{
    let sectors = max_pages
        .saturating_mul(sectors_per_page.get())
        .saturating_add(u64::from(sector_in_cluster));
    u32::try_from(sectors.div_ceil(sectors_per_cluster.get()))
        .unwrap_or(u32::MAX)
        .max(1)
}

/// The sector past a file's last byte, for a read at byte `offset_in_sector`
/// of `sector` with `left_in_file` bytes of the file from there, were the
/// rest of the file to follow `sector` on the device: the bound a run fill
/// takes beside the chain's contiguous span ([`contiguous_clusters`]).
#[must_use]
pub fn file_end_sector(
    sector: u64,
    offset_in_sector: u64,
    left_in_file: u64,
    bytes_per_sector: NonZeroU64,
) -> u64
{
    sector.saturating_add(
        offset_in_sector
            .saturating_add(left_in_file)
            .div_ceil(bytes_per_sector.get()),
    )
}

/// One sector's share of a file write ([`sector_write`]), which writes the
/// file's bytes from its old size, or from the payload's offset when that is
/// lower, to the payload's end: zeros up to the offset, then the payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectorWrite
{
    /// Zero bytes written first, from the byte's offset in its sector.
    pub zeros: usize,
    /// Payload bytes written after them.
    pub data: usize,
    /// The sector holds bytes below the file's old size that the share does
    /// not cover, so it is read before it is written. Otherwise it is written
    /// from a zeroed buffer: every byte it holds outside the share lies past
    /// the file's new end.
    pub read_first: bool,
}

/// The share of the sector holding file byte `at` (at `pos`, its
/// [`file_position`]) in a write of the file's bytes from `at` to `end`,
/// where the payload starts at `offset` and the file held `old_size` bytes
/// before the write. Bytes from `at` below `offset` are the gap between the
/// old end and the payload, written as zeros. `None` when `at` is not below
/// `end`, or `pos` does not place `at` in its sector.
#[must_use]
pub fn sector_write(
    pos: &FilePosition,
    at: u64,
    offset: u64,
    end: u64,
    old_size: u64,
) -> Option<SectorWrite>
{
    let left = u64::try_from(pos.left_in_sector).ok()?;
    let share = end.checked_sub(at).filter(|&n| n > 0)?.min(left);
    let zeros = offset.saturating_sub(at).min(share);
    let sector_start = at.checked_sub(u64::try_from(pos.offset_in_sector).ok()?)?;
    let keeps_head = pos.offset_in_sector > 0 && sector_start < old_size;
    let keeps_tail = share < left && at.checked_add(share)? < old_size;
    Some(SectorWrite {
        zeros: usize::try_from(zeros).ok()?,
        data: usize::try_from(share.checked_sub(zeros)?).ok()?,
        read_first: keeps_head || keeps_tail,
    })
}

// ── Directory entry ─────────────────────────────────────────────────────────

/// Maximum FAT long-file-name length, in UCS-2 code units.
pub const MAX_LFN_CHARS: usize = 255;

/// Maximum buffer size needed to hold a UTF-8-encoded FAT long name.
///
/// Each UCS-2 code unit encodes to at most three UTF-8 bytes (BMP);
/// surrogate pairs (two code units) encode to four UTF-8 bytes, so the
/// per-code-unit ceiling holds. `255 * 3` is the worst-case bound.
pub const MAX_LFN_UTF8: usize = MAX_LFN_CHARS * 3;

/// A parsed directory entry.
///
/// Carries the on-disk 8.3 fields plus an optional UTF-8-assembled
/// long file name (`lfn[..lfn_len]`). When `lfn_len == 0` the caller
/// MUST fall back to the 8.3 form, honouring `nt_case`.
#[derive(Clone, Copy)]
pub struct DirEntry
{
    /// 8.3 name (space-padded, uppercase per FAT spec).
    pub name: [u8; 11],
    /// `DIR_NTRes` byte 12: bit 0x08 = base lowercase, bit 0x10 =
    /// extension lowercase. Honoured by [`DirEntry::write_display_name`]
    /// when no LFN run accompanies this entry.
    pub nt_case: u8,
    pub attr: u8,
    pub cluster: u32,
    pub size: u32,
    /// Long file name, UTF-8 encoded. Populated only when a valid LFN
    /// run preceded the 8.3 entry and the run's checksum matches.
    pub lfn: [u8; MAX_LFN_UTF8],
    /// Length of `lfn` in bytes; `0` means "no LFN, use 8.3 fallback".
    pub lfn_len: u16,
}

impl DirEntry
{
    /// Bare 8.3 entry with no accompanying LFN.
    fn from_83(name: [u8; 11], nt_case: u8, attr: u8, cluster: u32, size: u32) -> Self
    {
        Self {
            name,
            nt_case,
            attr,
            cluster,
            size,
            lfn: [0; MAX_LFN_UTF8],
            lfn_len: 0,
        }
    }

    /// Write the user-visible name into `out`: the long name when one is
    /// present and its UTF-8 form holds at most `max_name` bytes, else the
    /// NT-case-aware 8.3 name, which a lookup accepts as well. A long name
    /// of up to 255 UCS-2 units can take up to [`MAX_LFN_UTF8`] bytes, more
    /// than a protocol's name may carry, and such an entry is listed under
    /// its short name rather than not at all. Returns the number of bytes
    /// written.
    ///
    /// `out` must be at least [`MAX_LFN_UTF8`] bytes; the function
    /// silently truncates otherwise.
    #[must_use]
    pub fn write_display_name(&self, out: &mut [u8], max_name: usize) -> usize
    {
        if self.lfn_len > 0 && usize::from(self.lfn_len) <= max_name
        {
            let lfn = self.lfn.iter().take(usize::from(self.lfn_len)).copied();
            return fill(out, lfn);
        }
        write_83_with_case(&self.name, self.nt_case, out)
    }
}

// ── LFN accumulator ─────────────────────────────────────────────────────────

/// LFN run accumulator.
///
/// FAT long file names are stored as a run of pseudo-directory entries
/// (attr `0x0F`) immediately preceding the trailing 8.3 entry. The run
/// appears in reverse order — sequence `N` first with the `0x40`
/// last-of-run flag, then `N-1`, …, down to `1`. Every entry in the
/// run carries the same `LDIR_Chksum` (byte 13), which equals
/// [`lfn_checksum`] computed over the trailing 8.3 name.
///
/// The accumulator stores characters in UCS-2 at their natural
/// position so that out-of-order or partial runs are detected and
/// discarded rather than producing a scrambled name.
pub struct LfnAccum
{
    /// UCS-2 code units indexed by their final position in the name.
    chars: [u16; MAX_LFN_CHARS],
    /// Number of valid UCS-2 code units in `chars`.
    len: usize,
    /// Checksum copied from the run's first (highest-seq) entry; every
    /// other entry in the run must carry the same value.
    chksum: u8,
    /// Sequence number of the most recently accepted entry. The next
    /// expected entry's seq is `last_seq - 1`; the run terminates at
    /// seq `1`.
    last_seq: u8,
    /// True once the run's first entry (the one carrying the `0x40`
    /// flag) has been consumed; used to detect mid-run orphans.
    saw_last: bool,
    /// True iff the accumulator currently holds a coherent partial or
    /// complete run.
    active: bool,
}

impl LfnAccum
{
    /// An empty accumulator holding no run.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            chars: [0; MAX_LFN_CHARS],
            len: 0,
            chksum: 0,
            last_seq: 0,
            saw_last: false,
            active: false,
        }
    }

    /// Discard any in-flight run, returning the accumulator to its empty state.
    pub fn reset(&mut self)
    {
        self.len = 0;
        self.chksum = 0;
        self.last_seq = 0;
        self.saw_last = false;
        self.active = false;
    }

    /// Process one 32-byte LFN directory entry (`raw[11] == 0x0F`).
    ///
    /// Performs the run-ordering and checksum-consistency checks
    /// documented on [`LfnAccum`]; rejects the in-flight run on any
    /// violation so a malformed run cannot poison a subsequent valid
    /// one.
    pub fn add_lfn_entry(&mut self, raw: &[u8; 32])
    {
        // Deleted-LFN-slot sentinel — discard the run; the trailing 8.3
        // entry (if any) is also deleted and will be skipped.
        if raw[0] == 0xE5
        {
            self.reset();
            return;
        }

        let is_last = raw[0] & 0x40 != 0;
        let seq = raw[0] & 0x3F;
        // Per the FAT spec, seq is in 1..=20 (20 slots × 13 chars =
        // 260, capped to 255 by the protocol). The slot holds name
        // positions from `(seq - 1) * 13`.
        let Some(base) = usize::from(seq)
            .checked_sub(1)
            .filter(|&slot| slot < MAX_LFN_CHARS.div_ceil(13))
            .and_then(|slot| slot.checked_mul(13))
        else
        {
            self.reset();
            return;
        };
        let chksum = raw[13];

        if is_last
        {
            // Start of a new run — entries appear in reverse order.
            self.reset();
            self.active = true;
            self.saw_last = true;
            self.chksum = chksum;
            self.last_seq = seq;
            // Provisional length: seq*13 chars capped at MAX_LFN_CHARS
            // (a 20-slot run spans 260 positions), trimmed downward when
            // the first 0x0000 / 0xFFFF terminator is observed below.
            self.len = (seq as usize * 13).min(MAX_LFN_CHARS);
        }
        else
        {
            if !self.saw_last || chksum != self.chksum || self.last_seq.checked_sub(1) != Some(seq)
            {
                self.reset();
                return;
            }
            self.last_seq = seq;
        }

        // The slot's 13 UCS-2 characters, in three runs of the 32-byte
        // entry: 5 at byte 1, 6 at byte 14, 2 at byte 28.
        let mut saw_terminator = false;
        for (k, &at) in LFN_UNIT_OFFSETS.iter().enumerate()
        {
            // `base` is at most 247 and `k` below 13, so this never wraps.
            let pos = base.wrapping_add(k);
            let (Some(slot), Some(&pair)) = (
                self.chars.get_mut(pos),
                raw.get(at..).and_then(<[u8]>::first_chunk::<2>),
            )
            else
            {
                break;
            };
            let ch = u16::from_le_bytes(pair);
            if ch == 0x0000 || ch == 0xFFFF
            {
                if !saw_terminator
                {
                    saw_terminator = true;
                    if pos < self.len
                    {
                        self.len = pos;
                    }
                }
                continue;
            }
            *slot = ch;
        }
    }

    /// Validate the assembled run against `sfn`'s checksum.
    ///
    /// Returns `true` when the run is complete (seq counted down to 1)
    /// and the checksum matches. Callers MUST gate
    /// [`Self::assemble_utf8`] on this; an unvalidated run can carry
    /// scrambled bytes from an earlier orphaned LFN sequence.
    #[must_use]
    pub fn validate(&self, sfn: &[u8; 11]) -> bool
    {
        self.active && self.saw_last && self.last_seq == 1 && lfn_checksum(sfn) == self.chksum
    }

    /// Decode the accumulated UCS-2 code units into UTF-8.
    ///
    /// Returns the byte length on success; `None` on buffer overflow
    /// or malformed surrogate pairs (an unpaired surrogate, or a high
    /// surrogate followed by a non-low-surrogate code unit).
    #[must_use]
    pub fn assemble_utf8(&self, out: &mut [u8]) -> Option<usize>
    {
        let units = self.chars.get(..self.len).unwrap_or(&self.chars);
        let mut at = 0usize;
        let mut pos = 0usize;
        while let Some(rest) = units.get(at..).filter(|rest| !rest.is_empty())
        {
            let (width, end) = utf8_step(rest, out, pos)?;
            // `width` is at most `rest.len()`, so this never saturates.
            at = at.saturating_add(width);
            pos = end;
        }
        Some(pos)
    }

    /// Case-insensitive ASCII match between the assembled LFN and `name`.
    ///
    /// Used by the directory by-name scan. Non-ASCII code units compare
    /// exactly (no full Unicode case folding); ASCII letters fold against
    /// `name`'s ASCII letters.
    #[must_use]
    pub fn matches(&self, name: &[u8]) -> bool
    {
        if !self.active || !self.saw_last || self.last_seq != 1
        {
            return false;
        }
        // Compare a character at a time, as [`utf8_step`] writes it, so no
        // buffer holds the whole form.
        let units = self.chars.get(..self.len).unwrap_or(&self.chars);
        let mut at = 0usize;
        let mut pos = 0usize;
        while let Some(rest) = units.get(at..).filter(|rest| !rest.is_empty())
        {
            let mut ch = [0u8; 4];
            let Some((width, len)) = utf8_step(rest, &mut ch, 0)
            else
            {
                return false;
            };
            let Some(part) = pos.checked_add(len).and_then(|end| name.get(pos..end))
            else
            {
                return false;
            };
            // A fixed count of four, the most one character takes, so a
            // proof's unwinding of the compare does not depend on `len`.
            let same = (0..4).all(|k| {
                k >= len
                    || ch
                        .get(k)
                        .zip(part.get(k))
                        .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
            });
            if !same
            {
                return false;
            }
            // `width` is at most `rest.len()`, and `pos` indexes `name`, so
            // neither saturates.
            at = at.saturating_add(width);
            pos = pos.saturating_add(len);
        }
        pos == name.len()
    }
}

/// One step of [`LfnAccum::assemble_utf8`]: write the UTF-8 form of the
/// character the UTF-16 code units `units` start with into `out` at `pos`.
/// Returns the code units the character takes and the position past its
/// bytes; `None`, with `out` unchanged, when `units` is empty or starts with
/// an unpaired surrogate, or the bytes do not fit `out`.
fn utf8_step(units: &[u16], out: &mut [u8], pos: usize) -> Option<(usize, usize)>
{
    let ch = char::decode_utf16(units.iter().copied()).next()?.ok()?;
    let end = pos.checked_add(ch.len_utf8())?;
    ch.encode_utf8(out.get_mut(pos..end)?);
    Some((ch.len_utf16(), end))
}

impl Default for LfnAccum
{
    fn default() -> Self
    {
        Self::new()
    }
}

/// Byte offsets of a long-name slot's 13 UCS-2 characters, in three runs of
/// the 32-byte entry: 5 at byte 1, 6 at byte 14, 2 at byte 28.
const LFN_UNIT_OFFSETS: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];

/// FAT LFN checksum: rotate-right-1 + add, computed over the 11-byte 8.3 name.
///
/// Defined by the Microsoft FAT specification as the value every LFN
/// slot in a run carries at byte offset 13 (`LDIR_Chksum`). Used by
/// readers to validate that an LFN run actually belongs to the
/// trailing 8.3 entry rather than to an orphaned earlier run.
#[must_use]
pub fn lfn_checksum(name: &[u8; 11]) -> u8
{
    let mut sum: u8 = 0;
    for &b in name
    {
        let lsb = sum & 1;
        sum = (sum >> 1)
            .wrapping_add(if lsb != 0 { 0x80 } else { 0 })
            .wrapping_add(b);
    }
    sum
}

// ── Entry parsing ───────────────────────────────────────────────────────────

/// Parse a single 32-byte FAT directory entry.
///
/// Returns `None` for end-of-directory (`0x00`), deleted (`0xE5`), LFN
/// (`attr=0x0F`), and volume-label (`ATTR_VOLUME_ID`, attr bit `0x08`)
/// entries. The returned [`DirEntry`] carries `lfn_len = 0`; callers that
/// have accumulated an LFN run via [`LfnAccum`] populate `lfn` / `lfn_len`
/// themselves.
#[must_use]
pub fn parse_dir_entry(raw: &[u8; 32]) -> Option<DirEntry>
{
    if raw[0] == 0x00
    {
        return None;
    }
    if raw[0] == 0xE5
    {
        return None;
    }
    if raw[11] == 0x0F || raw[11] & 0x08 != 0
    {
        return None;
    }

    let mut name = [0u8; 11];
    name.copy_from_slice(&raw[..11]);

    let attr = raw[11];
    let nt_case = raw[12];
    let cluster_hi = u16::from_le_bytes([raw[20], raw[21]]);
    let cluster_lo = u16::from_le_bytes([raw[26], raw[27]]);
    let cluster = (u32::from(cluster_hi) << 16) | u32::from(cluster_lo);
    let size = u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]);

    Some(DirEntry::from_83(name, nt_case, attr, cluster, size))
}

/// Check if an 8.3 directory entry name matches a path component.
///
/// The path component is converted to uppercase and compared against
/// the space-padded 8.3 name in the directory entry. A component whose
/// base is longer than 8 bytes or whose extension is longer than 3 spells
/// no short name and matches none: it names an entry by its long name only,
/// so a long name never matches another entry's short name by its prefix.
#[must_use]
pub fn name_matches(entry_name: &[u8; 11], component: &[u8]) -> bool
{
    let mut padded = [b' '; 11];
    // The base is the component up to its first dot, the extension what
    // follows that dot. `splitn` always yields the base, so its fallback is
    // never taken.
    let mut parts = component.splitn(2, |&b| b == b'.');
    let base = parts.next().unwrap_or_default();
    let ext = parts.next().unwrap_or_default();
    if base.len() > 8 || ext.len() > 3
    {
        return false;
    }
    for (dst, &b) in padded[..8].iter_mut().zip(base)
    {
        *dst = to_upper(b);
    }
    for (dst, &b) in padded[8..].iter_mut().zip(ext)
    {
        *dst = to_upper(b);
    }
    *entry_name == padded
}

/// ASCII uppercase fold of one byte; non-ASCII-lowercase bytes pass through unchanged.
#[must_use]
pub fn to_upper(b: u8) -> u8
{
    b.to_ascii_uppercase()
}

/// `bytes` without its trailing space padding.
fn trim_spaces(mut bytes: &[u8]) -> &[u8]
{
    while let [rest @ .., b' '] = bytes
    {
        bytes = rest;
    }
    bytes
}

/// Copy `src` into the front of `out` until either runs out; returns the
/// bytes written.
fn fill(out: &mut [u8], src: impl Iterator<Item = u8>) -> usize
{
    let mut written = 0usize;
    for (dst, b) in out.iter_mut().zip(src)
    {
        *dst = b;
        // At most `out.len()` bytes are written, so this never saturates.
        written = written.saturating_add(1);
    }
    written
}

/// Format an 8.3 entry honouring NT case-flag bits.
///
/// Bit `0x08` of `nt_case` (`DIR_NTRes` byte 12) indicates the base
/// portion was originally lowercase; bit `0x10` indicates the
/// extension was lowercase. Modern Windows / Linux fatfs surface
/// `boot.conf` and similar names lowercase by honouring these flags
/// even when no LFN entry accompanies the 8.3 record.
fn write_83_with_case(raw: &[u8; 11], nt_case: u8, out: &mut [u8]) -> usize
{
    let lower_base = nt_case & 0x08 != 0;
    let lower_ext = nt_case & 0x10 != 0;
    let fold = |lower: bool| move |&b: &u8| if lower { b.to_ascii_lowercase() } else { b };

    let base = trim_spaces(&raw[..8]).iter().map(fold(lower_base));
    let ext = trim_spaces(&raw[8..]);
    let dot = (!ext.is_empty()).then_some(b'.');
    fill(out, base.chain(dot).chain(ext.iter().map(fold(lower_ext))))
}

// ── Removal slot run ────────────────────────────────────────────────────────

/// Maximum directory slots one entry occupies: a 20-slot LFN run
/// (255 chars / 13 chars per slot) plus the trailing 8.3 entry.
pub const MAX_SLOT_RUN: usize = MAX_LFN_CHARS.div_ceil(13) + 1;

/// Up to [`MAX_SLOT_RUN`] slot positions, in the order they were pushed.
struct SlotRun<L>
{
    slots: [L; MAX_SLOT_RUN],
    len: usize,
}

impl<L: Copy + Default> SlotRun<L>
{
    fn new() -> Self
    {
        Self {
            slots: [L::default(); MAX_SLOT_RUN],
            len: 0,
        }
    }

    fn clear(&mut self)
    {
        self.len = 0;
    }

    fn len(&self) -> usize
    {
        self.len
    }

    /// Append `loc`; a push to a full run is dropped.
    fn push(&mut self, loc: L)
    {
        if let Some(slot) = self.slots.get_mut(self.len)
        {
            *slot = loc;
            // `len` is below `MAX_SLOT_RUN` here, so this never saturates.
            self.len = self.len.saturating_add(1);
        }
    }

    fn as_slice(&self) -> &[L]
    {
        // `push` keeps `len` at most `MAX_SLOT_RUN`, so the fallback is never
        // taken.
        self.slots.get(..self.len).unwrap_or_default()
    }
}

/// Outcome of feeding one directory slot to [`RemoveRunScan::step`].
pub enum RemoveStep
{
    /// The slot did not end the scan.
    Continue,
    /// End-of-directory marker (`0x00`) reached without a match.
    EndOfDir,
    /// The 8.3 entry in this slot matched, by its long name or its short
    /// alias; [`RemoveRunScan::run`] lists every slot it occupies.
    Found
    {
        /// First cluster of the matched entry ([`DirEntry::cluster`]).
        cluster: u32,
    },
}

/// Slot-by-slot directory scan that locates an entry by name together with
/// every slot it occupies, so a removal can mark them all deleted.
///
/// The entry's run includes its LFN slots whenever they validate against the
/// 8.3 entry, whichever name matched: the Microsoft FAT specification deletes
/// an LFN run with its 8.3 entry, so a removal by short alias leaves no
/// orphan long name. LFN slots that do not validate (an orphaned earlier run,
/// a checksum mismatch) are not part of the run. `L` is the caller's slot
/// position; scan state carries across sector boundaries.
pub struct RemoveRunScan<L>
{
    lfn: LfnAccum,
    /// Positions of the LFN slots since the last run start (`0x40` flag);
    /// after a match, the matched entry's run.
    slots: SlotRun<L>,
}

impl<L: Copy + Default> RemoveRunScan<L>
{
    /// An empty scan: no LFN run accumulated, no slot positions recorded.
    #[must_use]
    pub fn new() -> Self
    {
        Self {
            lfn: LfnAccum::new(),
            slots: SlotRun::new(),
        }
    }

    fn reset(&mut self)
    {
        self.lfn.reset();
        self.slots.clear();
    }

    /// Every slot the entry the last [`RemoveStep::Found`] reported
    /// occupies: its LFN slots in on-disk order, then the 8.3 slot.
    /// Meaningful only after [`Self::step`] returns `Found`.
    #[must_use]
    pub fn run(&self) -> &[L]
    {
        self.slots.as_slice()
    }

    /// Feed the directory slot `raw`, found at `loc`, to the scan for the
    /// path component `name`.
    ///
    /// Returns [`RemoveStep::EndOfDir`] on an end-of-directory slot (`0x00`),
    /// [`RemoveStep::Found`] when `raw` is an 8.3 entry that `name` matches by
    /// its validated long name or its short alias (after which
    /// [`Self::run`] lists the entry's slots), and [`RemoveStep::Continue`]
    /// otherwise.
    pub fn step(&mut self, raw: &[u8; 32], loc: L, name: &[u8]) -> RemoveStep
    {
        if raw[0] == 0x00
        {
            return RemoveStep::EndOfDir;
        }
        if raw[0] == 0xE5
        {
            self.reset();
            return RemoveStep::Continue;
        }
        if raw[11] == 0x0F
        {
            // A run start discards the positions of any earlier slots, so a
            // validated run's positions are exactly its own (at most 20).
            if raw[0] & 0x40 != 0
            {
                self.slots.clear();
            }
            self.lfn.add_lfn_entry(raw);
            // The last slot stays free for the 8.3 entry.
            if self.slots.len() < MAX_SLOT_RUN - 1
            {
                self.slots.push(loc);
            }
            return RemoveStep::Continue;
        }
        if let Some(entry) = parse_dir_entry(raw)
        {
            let lfn_valid = self.lfn.validate(&entry.name);
            if (lfn_valid && self.lfn.matches(name)) || name_matches(&entry.name, name)
            {
                if !lfn_valid
                {
                    self.slots.clear();
                }
                self.slots.push(loc);
                return RemoveStep::Found {
                    cluster: entry.cluster,
                };
            }
        }
        self.reset();
        RemoveStep::Continue
    }
}

impl<L: Copy + Default> Default for RemoveRunScan<L>
{
    fn default() -> Self
    {
        Self::new()
    }
}

// ── Insertion slot run ──────────────────────────────────────────────────────

/// Slot-by-slot directory scan that finds a run of consecutive free slots
/// for a new entry (its LFN slots plus its 8.3 slot).
///
/// A deleted slot (`0xE5`) is free; an end-of-directory slot (`0x00`) is free
/// and, per the Microsoft FAT specification, so is every slot after it,
/// whatever its bytes. A run therefore continues through the slots past the
/// end-of-directory marker instead of stopping there, so the whole new entry
/// lands before any reader's end of scan. Any other slot is in use and
/// restarts the run. `L` is the caller's slot position; scan state carries
/// across sector and cluster boundaries.
///
/// A run that crossed the marker leaves the slots after it free only while
/// the slot right after the run reads as the new end of the directory: its
/// bytes may be anything, and a reader would parse them as an entry. The
/// scan therefore takes that slot too ([`Self::end_marker`]), for the
/// caller to write a `0x00` marker into before the entry.
pub struct FreeRunScan<L>
{
    slots: SlotRun<L>,
    count: usize,
    past_end: bool,
    end_marker: Option<L>,
}

impl<L: Copy + Default> FreeRunScan<L>
{
    /// A scan for a run of `count` free slots, clamped to `1..=MAX_SLOT_RUN`.
    #[must_use]
    pub fn new(count: usize) -> Self
    {
        Self {
            slots: SlotRun::new(),
            count: count.clamp(1, MAX_SLOT_RUN),
            past_end: false,
            end_marker: None,
        }
    }

    /// Whether the scan has passed the directory's end-of-directory marker,
    /// after which every slot is free and need not be read.
    #[must_use]
    pub fn past_end(&self) -> bool
    {
        self.past_end
    }

    /// The run found: `count` slot positions in on-disk order. Meaningful
    /// only once [`Self::run_complete`] holds.
    #[must_use]
    pub fn run(&self) -> &[L]
    {
        self.slots.as_slice()
    }

    /// Whether the run holds `count` slots. At the end of a directory that
    /// cannot take another slot (the end of its chain or of the FAT16 root
    /// area), a complete run is the result even when [`Self::step`] has not
    /// returned `true`: the directory then ends with the run, and no slot
    /// after it needs a marker.
    #[must_use]
    pub fn run_complete(&self) -> bool
    {
        self.slots.len() >= self.count
    }

    /// The slot right after a run that crossed the end-of-directory marker,
    /// which the caller marks `0x00` so that the new entry is again followed
    /// by the end of the directory. `None` while the scan has not reached
    /// it, and for a run that ended before the marker, which the old marker
    /// still follows.
    #[must_use]
    pub fn end_marker(&self) -> Option<L>
    {
        self.end_marker
    }

    /// Feed the slot at `loc` whose first byte is `first`; once the scan is
    /// [past the end](Self::past_end) the byte is ignored. Returns `true`
    /// when the scan needs no further slot: the run holds `count` slots and,
    /// when it crossed the marker, the slot after it was fed as well
    /// ([`Self::end_marker`]). A step after that changes nothing and
    /// returns `true` again.
    pub fn step(&mut self, first: u8, loc: L) -> bool
    {
        if self.run_complete()
        {
            if self.past_end && self.end_marker.is_none()
            {
                self.end_marker = Some(loc);
            }
            return true;
        }
        if first == 0x00
        {
            self.past_end = true;
        }
        if self.past_end || first == 0xE5
        {
            self.slots.push(loc);
        }
        else
        {
            self.slots.clear();
        }
        self.run_complete() && !self.past_end
    }
}

// ── Long-name encoding ──────────────────────────────────────────────────────

/// Encode the UTF-8 name `name` as the UTF-16 code units of a FAT long name
/// (UCS-2, with a character outside the Basic Multilingual Plane as a
/// surrogate pair, the form [`LfnAccum::assemble_utf8`] decodes), into
/// `out`. Returns the code-unit count.
///
/// Returns `None` when `name` is not UTF-8, holds U+0000 or U+FFFF, whose
/// code units a long name's slots take as its end
/// ([`LfnAccum::add_lfn_entry`]), or needs more than [`MAX_LFN_CHARS`] code
/// units.
#[must_use]
pub fn encode_lfn(name: &[u8], out: &mut [u16; MAX_LFN_CHARS]) -> Option<usize>
{
    let mut len = 0usize;
    let mut at = 0usize;
    while let Some(rest) = name.get(at..).filter(|rest| !rest.is_empty())
    {
        let (ch, width) = utf8_char(rest)?;
        // `width` is at most `rest.len()`, so this never saturates.
        at = at.saturating_add(width);
        let mut units = [0u16; 2];
        for &unit in ch.encode_utf16(&mut units).iter()
        {
            if unit == 0x0000 || unit == 0xFFFF
            {
                return None;
            }
            *out.get_mut(len)? = unit;
            // `len` indexes `out`, so this never saturates.
            len = len.saturating_add(1);
        }
    }
    Some(len)
}

/// The UTF-8 character `bytes` starts with and its width in bytes, by the
/// table of well-formed byte sequences (Unicode § 3.9, Table 3-7; RFC 3629
/// § 4); `None` when `bytes` starts with none, an empty `bytes` included.
pub(crate) fn utf8_char(bytes: &[u8]) -> Option<(char, usize)>
{
    let lead = *bytes.first()?;
    // The width, the range of the second byte, and the lead's payload bits.
    let (width, low, high, bits) = match lead
    {
        0x00..=0x7F => return Some((char::from(lead), 1)),
        0xC2..=0xDF => (2, 0x80, 0xBF, lead & 0x1F),
        0xE0 => (3, 0xA0, 0xBF, lead & 0x0F),
        0xE1..=0xEC | 0xEE..=0xEF => (3, 0x80, 0xBF, lead & 0x0F),
        0xED => (3, 0x80, 0x9F, lead & 0x0F),
        0xF0 => (4, 0x90, 0xBF, lead & 0x07),
        0xF1..=0xF3 => (4, 0x80, 0xBF, lead & 0x07),
        0xF4 => (4, 0x80, 0x8F, lead & 0x07),
        _ => return None,
    };
    let mut scalar = u32::from(bits);
    for (k, &byte) in bytes.get(1..width)?.iter().enumerate()
    {
        let (lo, hi) = if k == 0 { (low, high) } else { (0x80, 0xBF) };
        if !(lo..=hi).contains(&byte)
        {
            return None;
        }
        scalar = scalar.wrapping_shl(6) | u32::from(byte & 0x3F);
    }
    Some((char::from_u32(scalar)?, width))
}

/// Attribute byte of a long-name directory slot.
pub const ATTR_LFN: u8 = 0x0F;

/// Flag `OR`ed into the sequence number of a long-name run's last slot, the
/// one written first on disk.
const LFN_LAST_FLAG: u8 = 0x40;

/// The long-name slot `seq` (from 1) of the name `units`, its UTF-16 code
/// units ([`encode_lfn`]), carrying the 8.3 checksum `chksum`
/// ([`lfn_checksum`]); `is_last` marks the run's last slot. The slot holds
/// units `(seq - 1) * 13` onward; a position past the name holds a single
/// `0x0000` terminator, then `0xFFFF` padding. The form
/// [`LfnAccum::add_lfn_entry`] decodes.
///
/// `None` when `seq` is 0 or past the slots of a [`MAX_LFN_CHARS`] name.
#[must_use]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`is_last` is the last-slot bit the slot's sequence byte encodes"
)]
pub fn pack_lfn_slot(seq: u8, is_last: bool, chksum: u8, units: &[u16]) -> Option<[u8; 32]>
{
    let base = usize::from(seq)
        .checked_sub(1)
        .filter(|&slot| slot < MAX_LFN_CHARS.div_ceil(13))?
        .checked_mul(13)?;
    let mut chars = [0xFFFFu16; 13];
    for (pos, ch) in (base..).zip(chars.iter_mut())
    {
        *ch = match units.get(pos)
        {
            Some(&unit) => unit,
            None if pos == units.len() => 0x0000,
            None => 0xFFFF,
        };
    }
    let bytes = chars.map(u16::to_le_bytes);
    // The 13 characters lie in three runs of the slot: 5 at byte 1, 6 at
    // byte 14, 2 at byte 28.
    let (first, rest) = bytes.as_flattened().split_at_checked(10)?;
    let (second, third) = rest.split_at_checked(12)?;
    let mut slot = [0u8; 32];
    slot[0] = if is_last { seq | LFN_LAST_FLAG } else { seq };
    slot[1..11].copy_from_slice(first);
    slot[11] = ATTR_LFN;
    slot[13] = chksum;
    slot[14..26].copy_from_slice(second);
    // FirstClusLO, bytes 26 and 27, is zero in a long-name slot.
    slot[28..32].copy_from_slice(third);
    Some(slot)
}

// ── Short-name numeric tails ────────────────────────────────────────────────

/// Largest numeric tail the Microsoft FAT specification's short-name scheme
/// generates (`~999999`): six digits after the `~` in an eight-byte base.
pub const MAX_NUMERIC_TAIL: u32 = 999_999;

/// Most entries a FAT directory holds (the specification caps a directory
/// at 65536 32-byte entries). A directory therefore always has a free tail
/// at or below `DIR_ENTRIES_MAX + 1`.
pub const DIR_ENTRIES_MAX: u32 = 65_536;

/// Most clusters a directory's chain holds on a volume of `total_clusters`
/// clusters of `sectors_per_cluster` sectors of `bytes_per_sector` bytes:
/// the clusters [`DIR_ENTRIES_MAX`] 32-byte entries (2 MiB) fill, rounded
/// up, and never more than the volume has. A directory walk past it has met
/// a chain the specification does not allow, a cycle among them, so it
/// stops there in time bounded by the directory size rather than the
/// volume's. A zero cluster size, which mount refuses, gives 0.
#[must_use]
pub fn dir_chain_limit(total_clusters: u32, sectors_per_cluster: u8, bytes_per_sector: u16) -> u32
{
    // A u8 by u16 product, and 65536 * 32, fit a u32: neither saturates.
    let cluster_bytes = u32::from(sectors_per_cluster).saturating_mul(u32::from(bytes_per_sector));
    let Some(cluster_bytes) = NonZeroU32::new(cluster_bytes)
    else
    {
        return 0;
    };
    DIR_ENTRIES_MAX
        .saturating_mul(32)
        .div_ceil(cluster_bytes.get())
        .min(total_clusters)
}

/// The short name `basis` (eight base bytes then three extension bytes,
/// space padded, as [`numeric_tail_basis`] builds) takes with numeric tail
/// `tail` (`1..=`[`MAX_NUMERIC_TAIL`]): the base keeps as many leading bytes
/// as fit before `~` and the tail's digits within eight bytes, as the
/// specification's numeric-tail generation does.
///
/// Returns `None` for a tail outside `1..=MAX_NUMERIC_TAIL`.
#[must_use]
pub fn compose_tailed_name(basis: &[u8; 11], tail: u32) -> Option<[u8; 11]>
{
    if !(1..=MAX_NUMERIC_TAIL).contains(&tail)
    {
        return None;
    }
    // The tail's decimal digits, right-aligned in a space-filled buffer.
    let mut digits = [b' '; 6];
    let mut n = tail;
    for slot in digits.iter_mut().rev()
    {
        if n == 0
        {
            break;
        }
        *slot = ascii_digit(n % 10)?;
        n /= 10;
    }
    let digits = digits.trim_ascii_start();
    let base = trim_spaces(&basis[..8]);
    // At most six digits, so the subtraction never saturates.
    let keep = base.len().min((8 - 1usize).saturating_sub(digits.len()));
    let tailed = base
        .iter()
        .take(keep)
        .chain(core::iter::once(&b'~'))
        .chain(digits);
    let mut out = [b' '; 11];
    for (dst, &b) in out[..8].iter_mut().zip(tailed)
    {
        *dst = b;
    }
    out[8..].copy_from_slice(&basis[8..]);
    Some(out)
}

/// The ASCII digit for `d`, or `None` when `d` is not a decimal digit.
fn ascii_digit(d: u32) -> Option<u8>
{
    char::from_digit(d, 10).and_then(|c| u8::try_from(c).ok())
}

/// The numeric tail `sfn` carries as a [`compose_tailed_name`] of `basis`,
/// or `None` when it is no such name.
#[must_use]
pub fn tail_of(sfn: &[u8; 11], basis: &[u8; 11]) -> Option<u32>
{
    if sfn[8..] != basis[8..]
    {
        return None;
    }
    // The digits after the base's last `~`; `None` when it has no `~`.
    let mut parts = trim_spaces(&sfn[..8]).rsplitn(2, |&b| b == b'~');
    let digits = parts.next()?;
    parts.next()?;
    if digits.len() > 6 || matches!(digits.first(), None | Some(&b'0'))
    {
        return None;
    }
    let mut tail = 0u32;
    for &d in digits
    {
        let digit = char::from(d).to_digit(10)?;
        // Six decimal digits fit a `u32`, so neither operation fails.
        tail = tail.checked_mul(10)?.checked_add(digit)?;
    }
    (compose_tailed_name(basis, tail)? == *sfn).then_some(tail)
}

/// The numeric tails one directory's short names use for one basis, for
/// tails up to `DIR_ENTRIES_MAX + 1`: the range the lowest free tail always
/// lies in, since the directory has at most [`DIR_ENTRIES_MAX`] entries.
pub struct TailSet
{
    bits: alloc::vec::Vec<u64>,
}

/// Words of [`TailSet`]'s bitmap: one bit per tail `0..=DIR_ENTRIES_MAX + 1`.
const TAIL_SET_WORDS: usize = (DIR_ENTRIES_MAX as usize + 2).div_ceil(64);

impl TailSet
{
    /// An empty set, its 8 KiB bitmap on the heap; `None` when the heap
    /// cannot hold it.
    #[must_use]
    pub fn try_new() -> Option<Self>
    {
        let mut bits = alloc::vec::Vec::new();
        bits.try_reserve_exact(TAIL_SET_WORDS).ok()?;
        bits.resize(TAIL_SET_WORDS, 0);
        Some(Self { bits })
    }

    /// Record the tail `sfn` carries for `basis`, if any.
    pub fn note(&mut self, sfn: &[u8; 11], basis: &[u8; 11])
    {
        if let Some(tail) = tail_of(sfn, basis)
            && let Some(word) = self.bits.get_mut(tail as usize / 64)
        {
            *word |= 1 << (tail % 64);
        }
    }

    /// The lowest tail no recorded name uses, or `None` when every tail the
    /// set covers is used (which a FAT directory cannot reach).
    #[must_use]
    pub fn lowest_free(&self) -> Option<u32>
    {
        (1..=DIR_ENTRIES_MAX + 1).find(|&t| {
            self.bits
                .get(t as usize / 64)
                .is_some_and(|word| word & (1 << (t % 64)) == 0)
        })
    }
}

/// Proofs of this crate's parsers of hostile input (docs/testing.md
/// § Bounded verification, Parser proofs), each a check of
/// [`property`] on every input up to its bounds:
///
/// - the BPB decode on every sector 0 of up to 512 bytes, which hold every
///   field and the boot signature (a longer sector's bytes past 512 are not
///   read), for every device block size and partition length, and the place
///   of every data cluster of every volume it accepts;
/// - the FAT entry read and write at every offset of every sector of up to
///   8 bytes, one past the bytes on either side of the widest entry, so an
///   entry inside, across and past the sector's end;
/// - the short-entry decode and its listed name on every 32-byte slot, and
///   the short-name match on every component of up to 13 bytes, one past
///   the longest spelled name (8, a dot, 3);
/// - the long-name run by induction: the empty accumulator (`new`, `reset`)
///   is in the invariant, and each slot steps it from any state in the
///   invariant as `property::lfn_step_holds` says, so after a run's slots
///   from its first down to number 1 the name is the units of its slots
///   before the first ending unit; its validation from any state; the
///   UTF-8 assembly of that name by induction too, each step from any two
///   code units into any position of any buffer of up to 8 bytes, and the
///   whole on every name of up to 3 units, which starts, steps past a
///   character of each width, stops at an unpaired surrogate, and ends;
///   with the match against a name on those names;
/// - the long-name encoding and its packing on every name of up to 5 bytes,
///   which holds a character of each UTF-8 width and one past the longest;
/// - each step of the removal and free-run scans from any state;
/// - the numeric tails, read from every short name and composed for every
///   tail, against every basis.
///
/// What lies outside them is the code that drives the steps: the loop of
/// [`LfnAccum::assemble_utf8`] over a name's units, the slot walks of the
/// `fatfs` driver that feed the accumulator and the scans, and the bit set
/// and search of [`TailSet`]. The fuzz target `fat`, the replay of the
/// checked-in inputs and the unit tests check them.
#[cfg(kani)]
mod proofs
{
    use super::{
        ATTR_LFN, FatType, FreeRunScan, LfnAccum, MAX_SLOT_RUN, MIN_SECTOR_SIZE, RemoveRunScan,
        SlotRun, property,
    };

    /// Either FAT width.
    fn any_fat_type() -> FatType
    {
        if kani::any()
        {
            FatType::Fat16
        }
        else
        {
            FatType::Fat32
        }
    }

    /// Any accumulator state in the invariant.
    fn any_lfn() -> LfnAccum
    {
        let acc = LfnAccum {
            chars: kani::any(),
            len: kani::any(),
            chksum: kani::any(),
            last_seq: kani::any(),
            saw_last: kani::any(),
            active: kani::any(),
        };
        kani::assume(property::lfn_invariant(&acc));
        acc
    }

    /// Any state in the invariant whose name has at most `max` units, the
    /// units past them zero: the assembly and the match read only the name's
    /// units (`chars[..len]`), and a slot's step writes its units whatever
    /// the others hold, so the rest cannot change what they do, and fixing
    /// them keeps the problem small.
    fn any_lfn_up_to(max: usize) -> LfnAccum
    {
        let mut chars = [0u16; super::MAX_LFN_CHARS];
        for unit in chars.iter_mut().take(max)
        {
            *unit = kani::any();
        }
        let acc = LfnAccum {
            chars,
            len: kani::any(),
            chksum: kani::any(),
            last_seq: kani::any(),
            saw_last: kani::any(),
            active: kani::any(),
        };
        kani::assume(acc.len <= max && property::lfn_invariant(&acc));
        acc
    }

    /// Any run of slot places of up to [`MAX_SLOT_RUN`].
    fn any_run() -> SlotRun<u32>
    {
        let run = SlotRun {
            slots: kani::any(),
            len: kani::any(),
        };
        kani::assume(run.len <= MAX_SLOT_RUN);
        run
    }

    /// BPB: the decode contract on the first `len` bytes of any 512-byte
    /// sector 0, `len` up to 512, for any device block size and partition
    /// length. The decode has no loop; the property's only loops are the
    /// short fixed reads of its fields, so an unwind bound of 5 covers them.
    #[kani::proof]
    #[kani::unwind(5)]
    fn every_boot_sector_holds_the_bpb_contract()
    {
        let sector: [u8; MIN_SECTOR_SIZE] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MIN_SECTOR_SIZE);
        property::bpb_holds(&sector[..len], kani::any(), kani::any());
    }

    /// Clusters: on every volume a 512-byte sector 0 describes that the
    /// decode accepts, any cluster lies in the data region exactly when it is
    /// one of its clusters, and a data cluster's FAT entry lies in the first
    /// FAT copy and its sectors in the volume and partition. No loop.
    #[kani::proof]
    #[kani::unwind(5)]
    fn every_data_cluster_lies_inside_its_fat_and_volume()
    {
        let sector: [u8; MIN_SECTOR_SIZE] = kani::any();
        property::geometry_cluster_holds(&sector, kani::any(), kani::any(), kani::any());
    }

    /// FAT entries: the entry of either width at any offset of any sector of
    /// up to 8 bytes is read and written in place. The longest loops walk the
    /// property's 6-byte copy, so an unwind bound of 8 covers them.
    #[kani::proof]
    #[kani::unwind(8)]
    fn every_fat_entry_is_read_and_written_in_place()
    {
        let sector: [u8; 8] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= sector.len());
        property::fat_entry_holds(&sector[..len], any_fat_type(), kani::any(), kani::any());
    }

    /// Short entries: every 32-byte slot is skipped or decoded, and listed
    /// under its short name, as the specification places its fields. The
    /// longest loops walk the 13-byte name buffer, so an unwind bound of 14
    /// covers them.
    #[kani::proof]
    #[kani::unwind(14)]
    fn every_directory_slot_holds_the_entry_contract()
    {
        let raw: [u8; 32] = kani::any();
        property::dir_entry_holds(&raw);
    }

    /// Short-name match: every component of up to 13 bytes matches any short
    /// name exactly when it spells it. The longest loops walk the component,
    /// so an unwind bound of 15 covers them.
    #[kani::proof]
    #[kani::unwind(15)]
    fn every_component_matches_the_short_name_it_spells()
    {
        let entry: [u8; 11] = kani::any();
        let component: [u8; 13] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= component.len());
        property::name_matches_holds(&entry, &component[..len]);
    }

    /// Base of the long-name run: a new accumulator, and one reset from any
    /// state, holds no run and stands in the invariant. No loop.
    #[kani::proof]
    fn an_lfn_accumulator_starts_and_resets_empty()
    {
        assert!(property::lfn_invariant(&LfnAccum::new()));
        let mut acc = any_lfn();
        acc.reset();
        assert!(property::lfn_invariant(&acc) && !acc.active && acc.len == 0);
    }

    /// Step of the long-name run: from any state in the invariant, any slot
    /// steps the run as the specification lays a run out, its units checked
    /// at any name position, so at every one. The longest loops walk the
    /// slot's 13 units, so an unwind bound of 14 covers them.
    #[kani::proof]
    #[kani::unwind(14)]
    fn each_long_name_slot_steps_its_run()
    {
        let acc = any_lfn();
        let raw: [u8; 32] = kani::any();
        property::lfn_step_holds(&acc, &raw, Some(kani::any()));
    }

    /// Validation: from any state, a run is valid for any short name exactly
    /// when it is complete and carries the name's checksum. The loops walk
    /// the 11-byte name, so an unwind bound of 12 covers them.
    #[kani::proof]
    #[kani::unwind(12)]
    fn a_run_is_valid_by_its_order_and_checksum()
    {
        let acc = any_lfn();
        let sfn: [u8; 11] = kani::any();
        property::validate_holds(&acc, &sfn);
    }

    /// Step of the name's UTF-8 assembly: any two code units, the most one
    /// character takes, and fewer, into any position of any buffer of up to
    /// 8 bytes, past the longest character's 4. The longest loop walks the
    /// buffer, so an unwind bound of 9 covers it.
    #[kani::proof]
    #[kani::unwind(9)]
    fn each_character_of_a_long_name_is_assembled()
    {
        let units: [u16; 2] = kani::any();
        let count: usize = kani::any();
        kani::assume(count <= units.len());
        property::utf8_step_holds(&units[..count], kani::any(), kani::any(), kani::any());
    }

    /// Base of the assembly: every name of up to 3 units, in any state, into
    /// any buffer, its forms held in 12 bytes (a 3-unit name's takes at most
    /// 9). The longest loops walk those 12 bytes, so an unwind bound of 13
    /// covers them.
    #[kani::proof]
    #[kani::unwind(13)]
    fn every_short_long_name_is_assembled()
    {
        let acc = any_lfn_up_to(3);
        property::assemble_holds::<12>(&acc, kani::any());
    }

    /// The match: every name of up to 3 units, in any state, against any
    /// name of up to 5 bytes, bounded as the assembly's.
    #[kani::proof]
    #[kani::unwind(13)]
    fn every_short_long_name_is_matched()
    {
        let acc = any_lfn_up_to(3);
        let name: [u8; 5] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= name.len());
        property::match_holds::<12>(&acc, &name[..len]);
    }

    /// A character of a name to encode: any start of up to 4 bytes, the most
    /// one character holds. The longest loops walk those 4 bytes, so an
    /// unwind bound of 6 covers them.
    #[kani::proof]
    #[kani::unwind(6)]
    fn each_character_of_a_name_to_encode_is_decoded()
    {
        let bytes: [u8; 4] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::utf8_char_holds(&bytes[..len]);
    }

    /// Encoding: every name of up to 4 bytes, one character of every width or
    /// up to four of the narrowest, is encoded as its UTF-16 code units, or
    /// refused, the units read back in 12 bytes. With the character read
    /// proven above, the loops walk at most those 4 bytes, so an unwind bound
    /// of 6 covers them.
    #[kani::proof]
    #[kani::unwind(6)]
    fn every_short_name_is_encoded()
    {
        let name: [u8; 4] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= name.len());
        property::encode_contract_holds::<12>(&name[..len]);
    }

    /// Packing: any slot of any name of up to 27 code units (three slots'
    /// worth, the third holding the terminator or padding) is laid out as the
    /// specification lays it out. With the accumulator's step proven above,
    /// which reads any slot so laid out, a name's slots read back. The longest
    /// loops walk the slot's 13 characters, so an unwind bound of 14 covers
    /// them.
    #[kani::proof]
    #[kani::unwind(14)]
    fn every_long_name_slot_is_packed_in_place()
    {
        let units: [u16; 27] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= units.len());
        property::pack_slot_holds(kani::any(), kani::any(), kani::any(), &units[..len]);
    }

    /// Step of the removal scan for a slot of the kind `long` names (a
    /// long-name slot, or any other), at any place, and any name of up to 3
    /// bytes, the accumulator compared at any name position, so at every one.
    /// A long-name slot's attribute is fixed, so the problem holds no other
    /// slot's path. The step's two parts are proven apart, each with the
    /// other's input held small. `places` takes a run of any length, up to
    /// 21 places, since the places a step records depend only on the run, on
    /// a long-name slot's first-slot bit and on whether the entry is found and
    /// its run valid: so an accumulator whose name is empty and the name `A`,
    /// which the short name alone matches or not, with the run valid or not;
    /// and a long-name slot of sequence 1, first or not, whose units are zero.
    /// Otherwise the run is empty and the accumulator's name has up to one unit
    /// ([`any_lfn_up_to`]), which against a name of up to 3 bytes takes both
    /// answers of `LfnAccum::matches`, proven above, and the slot's units are
    /// any.
    fn removal_step(long: bool, places: bool)
    {
        let scan = if places
        {
            let lfn = LfnAccum {
                chars: [0u16; super::MAX_LFN_CHARS],
                len: 0,
                chksum: kani::any(),
                last_seq: kani::any(),
                saw_last: kani::any(),
                active: kani::any(),
            };
            kani::assume(property::lfn_invariant(&lfn));
            RemoveRunScan {
                lfn,
                slots: any_run(),
            }
        }
        else
        {
            RemoveRunScan {
                lfn: any_lfn_up_to(1),
                slots: SlotRun {
                    slots: kani::any(),
                    len: 0,
                },
            }
        };
        let mut raw: [u8; 32] = if long && places
        {
            let mut raw = [0u8; 32];
            raw[0] = if kani::any() { 0x41 } else { 0x01 };
            raw[13] = kani::any();
            raw
        }
        else
        {
            kani::any()
        };
        if long
        {
            raw[11] = ATTR_LFN;
            kani::assume(raw[0] != 0xE5);
        }
        else
        {
            kani::assume(raw[0] == 0xE5 || raw[11] != ATTR_LFN);
        }
        let name: [u8; 3] = if places { [b'A', 0, 0] } else { kani::any() };
        let len: usize = if places { 1 } else { kani::any() };
        kani::assume(len <= name.len());
        property::remove_step_holds(&scan, &raw, kani::any(), &name[..len], Some(kani::any()));
    }

    /// Step of the removal scan, a long-name slot, the places it records
    /// ([`removal_step`]). The longest loops compare runs of up to 21
    /// places, so an unwind bound of 23 covers them.
    #[kani::proof]
    #[kani::unwind(23)]
    fn each_long_name_slot_steps_a_removal_scan_places()
    {
        removal_step(true, true);
    }

    /// Step of the removal scan, a long-name slot, the units it writes
    /// ([`removal_step`]). The longest loops walk the slot's 13 units, so an
    /// unwind bound of 14 covers them.
    #[kani::proof]
    #[kani::unwind(14)]
    fn each_long_name_slot_steps_a_removal_scan_name()
    {
        removal_step(true, false);
    }

    /// Step of the removal scan, any other slot, the places it records
    /// ([`removal_step`]), bounded as the long-name slot's.
    #[kani::proof]
    #[kani::unwind(23)]
    fn each_other_slot_steps_a_removal_scan_places()
    {
        removal_step(false, true);
    }

    /// Step of the removal scan, any other slot, the match it makes
    /// ([`removal_step`]). The longest loops walk the 11 bytes of a short
    /// name, so an unwind bound of 12 covers them.
    #[kani::proof]
    #[kani::unwind(12)]
    fn each_other_slot_steps_a_removal_scan_match()
    {
        removal_step(false, false);
    }

    /// Base and step of the free-run scan: a new scan for any count stands in
    /// the invariant, and from any state in it any slot steps the scan. The
    /// longest loops copy a run of up to 21 places, so an unwind bound of 23
    /// covers them.
    #[kani::proof]
    #[kani::unwind(23)]
    fn each_slot_steps_a_free_run_scan()
    {
        assert!(property::free_invariant(&FreeRunScan::<u32>::new(
            kani::any()
        )));
        let scan = FreeRunScan {
            slots: any_run(),
            count: kani::any(),
            past_end: kani::any(),
            end_marker: kani::any(),
        };
        kani::assume(property::free_invariant(&scan));
        property::free_step_holds(&scan, kani::any(), kani::any());
    }

    /// Numeric tails read: any short name's tail against any basis composes
    /// back to it. The longest loops walk the 11-byte names, so an unwind
    /// bound of 12 covers them.
    #[kani::proof]
    #[kani::unwind(12)]
    fn every_numeric_tail_read_composes_back()
    {
        let sfn: [u8; 11] = kani::any();
        let basis: [u8; 11] = kani::any();
        property::tail_read_holds(&sfn, &basis);
    }

    /// Numeric tails composed: any tail with any basis. The longest loops walk
    /// the 11-byte names and the tail's up to 6 digits, so an unwind bound of
    /// 12 covers them.
    #[kani::proof]
    #[kani::unwind(12)]
    fn every_numeric_tail_composes_its_name()
    {
        let basis: [u8; 11] = kani::any();
        property::compose_holds(&basis, kani::any());
    }

    /// Numeric tails round trip: any tail composed with any basis reads back
    /// from the name. The longest loops walk the 11-byte names, so an unwind
    /// bound of 12 covers them.
    #[kani::proof]
    #[kani::unwind(12)]
    fn every_composed_numeric_tail_reads_back()
    {
        let basis: [u8; 11] = kani::any();
        property::tail_round_trip_holds(&basis, kani::any());
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Build a BPB sector 0 with a valid boot signature and the given fields.
    #[expect(
        clippy::too_many_arguments,
        reason = "one argument per BPB field the tests vary, so each test states the geometry it \
                  exercises in one call"
    )]
    fn bpb_sector(
        bytes_per_sector: u16,
        sectors_per_cluster: u8,
        reserved: u16,
        num_fats: u8,
        root_entries: u16,
        total_sectors_16: u16,
        fat_size_16: u16,
        total_sectors_32: u32,
        fat_size_32: u32,
        root_cluster: u32,
        fsinfo: u16,
    ) -> [u8; 512]
    {
        let mut s = [0u8; 512];
        s[510] = 0x55;
        s[511] = 0xAA;
        s[11..13].copy_from_slice(&bytes_per_sector.to_le_bytes());
        s[13] = sectors_per_cluster;
        s[14..16].copy_from_slice(&reserved.to_le_bytes());
        s[16] = num_fats;
        s[17..19].copy_from_slice(&root_entries.to_le_bytes());
        s[19..21].copy_from_slice(&total_sectors_16.to_le_bytes());
        s[22..24].copy_from_slice(&fat_size_16.to_le_bytes());
        s[32..36].copy_from_slice(&total_sectors_32.to_le_bytes());
        s[36..40].copy_from_slice(&fat_size_32.to_le_bytes());
        s[44..48].copy_from_slice(&root_cluster.to_le_bytes());
        s[48..50].copy_from_slice(&fsinfo.to_le_bytes());
        s
    }

    /// A FAT16 volume: 4085 <= `total_clusters` < 65525.
    /// `data_start` = 1 + 2*32 + 32 = 97; clusters = (8192-97)/1 = 8095,
    /// within the 32 * 256 = 8192 entries one FAT holds.
    fn fat16_sector() -> [u8; 512]
    {
        bpb_sector(512, 1, 1, 2, 512, 8192, 32, 0, 0, 0, 0)
    }

    /// A FAT32 volume: large enough that `total_clusters` >= 65525.
    /// `data_start` = 32 + 2*2400 = 4832; clusters = (300000-4832)/1 = 295168,
    /// within the 2400 * 128 = 307200 entries one FAT holds.
    fn fat32_sector(fsinfo: u16) -> [u8; 512]
    {
        bpb_sector(512, 1, 32, 2, 0, 0, 0, 300_000, 2400, 2, fsinfo)
    }

    // The defect caught: a ceiling that drops below the floor on a small
    // machine, stops growing with RAM, or overflows on a huge one.
    #[test]
    fn the_slot_ceiling_is_the_floor_up_to_512_mib_and_grows_with_ram_past_it()
    {
        let mib = |n: u64| n * 256;
        assert_eq!(slot_ceiling(0), SLOT_COUNT);
        assert_eq!(slot_ceiling(mib(128)), SLOT_COUNT);
        assert_eq!(slot_ceiling(mib(512)), SLOT_COUNT);
        assert_eq!(slot_ceiling(mib(1024)), 2 * SLOT_COUNT);
        assert_eq!(slot_ceiling(mib(64 * 1024)), 128 * SLOT_COUNT);
        assert_eq!(
            slot_ceiling(u64::MAX),
            (u64::MAX / SLOT_RAM_DIVISOR) as usize
        );
    }

    /// An unreferenced, unskipped slot with a page cap, last used at `lru_seq`.
    fn idle(lru_seq: u64) -> VictimView
    {
        VictimView {
            referenced: false,
            has_cap: true,
            skipped: false,
            lru_seq,
        }
    }

    fn capless(lru_seq: u64) -> VictimView
    {
        VictimView {
            has_cap: false,
            ..idle(lru_seq)
        }
    }

    fn referenced(lru_seq: u64) -> VictimView
    {
        VictimView {
            referenced: true,
            ..idle(lru_seq)
        }
    }

    fn skipped(lru_seq: u64) -> VictimView
    {
        VictimView {
            skipped: true,
            ..idle(lru_seq)
        }
    }

    // The defect caught: a slot with no page cap (given back under memory
    // pressure, lost by a swap or a failed fill) chosen as the victim. Its
    // last-use number never moves, so once the cache is full it would be
    // every miss's pick, and every refill of it fails.
    #[test]
    fn lru_victim_passes_over_a_slot_with_no_page_cap()
    {
        assert_eq!(lru_victim([capless(1), idle(7), idle(5)]), Some(2));
        assert_eq!(lru_victim([capless(0)]), None);
    }

    #[test]
    fn lru_victim_takes_the_oldest_unreferenced_unskipped_slot_first_of_a_tie()
    {
        let slots = [referenced(1), skipped(2), idle(4), idle(3), idle(3)];
        assert_eq!(lru_victim(slots), Some(3));
        assert_eq!(lru_victim([]), None);
        assert_eq!(lru_victim([referenced(0), skipped(0)]), None);
    }

    // The defect caught: a release under memory pressure that gives back
    // every idle page leaves a cache that memmgr refuses pages at `Critical`
    // nothing to evict, so every miss fails until the level clears.
    #[test]
    fn keep_most_recent_keeps_the_newest_idle_slots_first_of_a_tie()
    {
        let slots = [idle(3), idle(9), idle(1), idle(7), idle(9), idle(5)];
        let mut kept = [true; 6];
        keep_most_recent(&slots, 3, &mut kept);
        assert_eq!(kept, [false, true, false, true, true, false]);
        keep_most_recent(&slots, 0, &mut kept);
        assert_eq!(kept, [false; 6]);
    }

    #[test]
    fn keep_most_recent_keeps_only_idle_slots_with_a_cap_the_caller_does_not_skip()
    {
        let slots = [referenced(9), capless(8), skipped(7), idle(2), idle(1)];
        let mut kept = [false; 5];
        keep_most_recent(&slots, 4, &mut kept);
        assert_eq!(kept, [false, false, false, true, true]);
    }

    #[test]
    fn walk_start_resumes_at_a_cursor_on_the_same_chain_and_epoch_at_or_before_the_target()
    {
        let cursor = ChainCursor {
            epoch: 3,
            first_cluster: 10,
            cluster_index: 5,
            cluster: 42,
        };
        assert_eq!(walk_start(Some(cursor), 3, 10, 5), (5, 42));
        assert_eq!(walk_start(Some(cursor), 3, 10, 9), (5, 42));
    }

    #[test]
    fn walk_start_begins_at_the_head_when_the_cursor_cannot_serve()
    {
        let cursor = ChainCursor {
            epoch: 3,
            first_cluster: 10,
            cluster_index: 5,
            cluster: 42,
        };
        // A target behind the cursor, a chain freed since, another chain,
        // and no cursor.
        assert_eq!(walk_start(Some(cursor), 3, 10, 4), (0, 10));
        assert_eq!(walk_start(Some(cursor), 4, 10, 9), (0, 10));
        assert_eq!(walk_start(Some(cursor), 3, 11, 9), (0, 11));
        assert_eq!(walk_start(None, 3, 10, 9), (0, 10));
    }

    #[test]
    fn contiguous_clusters_counts_consecutive_links_up_to_the_bound()
    {
        // 7 -> 8 -> 9 -> 12 -> end.
        let next = |c: u32| match c
        {
            7 => Some(8),
            8 => Some(9),
            9 => Some(12),
            _ => None,
        };
        assert_eq!(contiguous_clusters(7, 16, next), 3);
        assert_eq!(contiguous_clusters(7, 2, next), 2);
        assert_eq!(contiguous_clusters(12, 16, next), 1);
        assert_eq!(contiguous_clusters(7, 0, next), 1);
    }

    #[test]
    fn contiguous_clusters_stops_at_the_last_cluster_number()
    {
        assert_eq!(contiguous_clusters(u32::MAX, 4, |_| Some(0)), 1);
    }

    #[test]
    fn run_pages_covers_the_run_in_whole_pages_within_the_bound()
    {
        let spp = NonZeroU64::new(8).unwrap();
        // A run ending inside its third page takes three pages.
        assert_eq!(run_pages(16, 16 + 17, spp, 16), 3);
        assert_eq!(run_pages(16, 16 + 24, spp, 16), 3);
        // Capped at the bound, and never below one page.
        assert_eq!(run_pages(0, 8 * 100, spp, 16), 16);
        assert_eq!(run_pages(16, 16, spp, 16), 1);
        assert_eq!(run_pages(16, 3, spp, 16), 1);
        assert_eq!(run_pages(0, 8 * 100, spp, 0), 1);
    }

    #[test]
    fn run_cluster_bound_covers_the_run_from_the_cluster_start()
    {
        let spp = NonZeroU64::new(8).unwrap();
        let spc = NonZeroU64::new(8).unwrap();
        // 16 pages of 8 sectors, 3 sectors into the cluster: 131 sectors.
        assert_eq!(run_cluster_bound(16, spp, 3, spc), 17);
        assert_eq!(run_cluster_bound(16, spp, 0, spc), 16);
        assert_eq!(run_cluster_bound(1, NonZeroU64::MIN, 0, spc), 1);
        assert_eq!(run_cluster_bound(0, spp, 0, spc), 1);
        assert_eq!(
            run_cluster_bound(u64::MAX, spp, 0, NonZeroU64::MIN),
            u32::MAX
        );
    }

    #[test]
    fn file_end_sector_rounds_the_file_tail_up_to_whole_sectors()
    {
        let bps = NonZeroU64::new(512).unwrap();
        assert_eq!(file_end_sector(100, 0, 512, bps), 101);
        assert_eq!(file_end_sector(100, 10, 503, bps), 102);
        assert_eq!(file_end_sector(100, 10, 502, bps), 101);
        assert_eq!(file_end_sector(u64::MAX, 0, 1, bps), u64::MAX);
    }

    #[test]
    fn keep_most_recent_never_marks_a_slot_past_its_mark_buffer()
    {
        let mut kept = [false; 2];
        keep_most_recent(&[idle(1), idle(2), idle(3)], 2, &mut kept);
        assert_eq!(kept, [true, true]);
    }

    #[test]
    fn parse_bpb_geometry_rejects_missing_boot_signature()
    {
        let mut s = fat16_sector();
        s[510] = 0x00;
        assert!(matches!(
            parse_bpb_geometry(&s, 512, u64::MAX),
            Err(BpbError::BadSignature)
        ));
    }

    #[test]
    fn parse_bpb_geometry_rejects_zero_bytes_per_sector_or_sectors_per_cluster()
    {
        let zero_bps = bpb_sector(0, 4, 1, 2, 512, 8192, 20, 0, 0, 0, 0);
        assert!(matches!(
            parse_bpb_geometry(&zero_bps, 512, u64::MAX),
            Err(BpbError::ZeroDivisor)
        ));
        let zero_spc = bpb_sector(512, 0, 1, 2, 512, 8192, 20, 0, 0, 0, 0);
        assert!(matches!(
            parse_bpb_geometry(&zero_spc, 512, u64::MAX),
            Err(BpbError::ZeroDivisor)
        ));
    }

    #[test]
    fn parse_bpb_geometry_rejects_sectors_per_cluster_not_a_power_of_two()
    {
        // Defect caught: a cluster size the specification does not permit
        // was accepted and its cluster count divided out.
        for spc in [3u8, 6, 255]
        {
            let sector = bpb_sector(512, spc, 1, 2, 512, 60_000, 20, 0, 0, 0, 0);
            assert!(matches!(
                parse_bpb_geometry(&sector, 512, u64::MAX),
                Err(BpbError::BadGeometry)
            ));
        }
    }

    #[test]
    fn parse_bpb_geometry_detects_fat16_below_cluster_threshold()
    {
        let g = parse_bpb_geometry(&fat16_sector(), 512, u64::MAX)
            .ok()
            .expect("valid FAT16");
        assert!(matches!(g.fat_type, FatType::Fat16));
        assert_eq!(g.total_clusters, 8095);
        assert_eq!(g.data_start_sector, 97);
        assert_eq!(g.fat_size, 32);
        // FAT16 leaves FSInfo absent regardless of the bytes at offset 48.
        assert_eq!(g.fsinfo_sector, None);
    }

    #[test]
    fn parse_bpb_geometry_refuses_a_fat12_cluster_count()
    {
        // data_start = 1 + 2*20 + 32 = 73, one sector per cluster.
        let fat12 = bpb_sector(512, 1, 1, 2, 512, 73 + 4084, 20, 0, 0, 0, 0);
        assert!(matches!(
            parse_bpb_geometry(&fat12, 512, u64::MAX),
            Err(BpbError::Fat12)
        ));
        let g = parse_bpb_geometry(
            &bpb_sector(512, 1, 1, 2, 512, 73 + 4085, 20, 0, 0, 0, 0),
            512,
            u64::MAX,
        )
        .ok()
        .expect("the fewest clusters FAT16 has");
        assert!(matches!(g.fat_type, FatType::Fat16));
    }

    #[test]
    fn parse_bpb_geometry_detects_fat32_at_and_above_threshold()
    {
        let g = parse_bpb_geometry(&fat32_sector(1), 512, u64::MAX)
            .ok()
            .expect("valid FAT32");
        assert!(matches!(g.fat_type, FatType::Fat32));
        assert_eq!(g.total_clusters, 295_168);
        // fat_size_16 == 0 falls back to fat_size_32.
        assert_eq!(g.fat_size, 2400);
        assert_eq!(g.root_cluster, 2);
        assert_eq!(g.fsinfo_sector, Some(1));
    }

    #[test]
    fn parse_bpb_geometry_holds_fsinfo_sentinel_for_absent_fsinfo()
    {
        // 0xFFFF and 0 both mean "no FSInfo sector" → None (caller keeps u32::MAX).
        let absent = parse_bpb_geometry(&fat32_sector(0xFFFF), 512, u64::MAX)
            .ok()
            .expect("valid FAT32");
        assert_eq!(absent.fsinfo_sector, None);
        let zero = parse_bpb_geometry(&fat32_sector(0), 512, u64::MAX)
            .ok()
            .expect("valid FAT32");
        assert_eq!(zero.fsinfo_sector, None);
    }

    #[test]
    fn cluster_to_sector_maps_first_data_cluster_to_data_start()
    {
        // Cluster 2 is the first data cluster: it sits exactly at data_start.
        assert_eq!(cluster_to_sector(100, 8, 2), 100);
        // Cluster 3 is one cluster (8 sectors) further in.
        assert_eq!(cluster_to_sector(100, 8, 3), 108);
    }

    #[test]
    fn parse_bpb_geometry_refuses_a_sector_slice_shorter_than_512_bytes()
    {
        let s = fat16_sector();
        assert!(matches!(
            parse_bpb_geometry(&s[..511], 512, u64::MAX),
            Err(BpbError::UnsupportedSectorSize)
        ));
    }

    #[test]
    fn parse_bpb_geometry_rejects_sectors_other_than_the_device_block()
    {
        // A 4 KiB-sector volume on a 512-byte device, and the reverse: the
        // cache and FAT walker index one device block per sector.
        let large = bpb_sector(4096, 1, 1, 2, 512, 8192, 20, 0, 0, 0, 0);
        assert!(matches!(
            parse_bpb_geometry(&large, 512, u64::MAX),
            Err(BpbError::UnsupportedSectorSize)
        ));
        assert!(matches!(
            parse_bpb_geometry(&fat16_sector(), 4096, u64::MAX),
            Err(BpbError::UnsupportedSectorSize)
        ));
        // 1536 matches its device but is no FAT sector size.
        let odd = bpb_sector(1536, 1, 1, 2, 512, 8192, 20, 0, 0, 0, 0);
        assert!(matches!(
            parse_bpb_geometry(&odd, 1536, u64::MAX),
            Err(BpbError::UnsupportedSectorSize)
        ));
    }

    #[test]
    fn parse_bpb_geometry_decodes_a_4kn_volume_from_a_4096_byte_sector()
    {
        // A FAT32 volume of 4 KiB sectors: data_start = 32 + 2*300 = 632,
        // 300000 - 632 clusters, within 300 * 1024 = 307200 FAT entries.
        let mut s = [0u8; MAX_SECTOR_SIZE];
        s[..512].copy_from_slice(&bpb_sector(4096, 1, 32, 2, 0, 0, 0, 300_000, 300, 2, 1));
        let g = parse_bpb_geometry(&s, 4096, u64::MAX)
            .ok()
            .expect("4Kn FAT32");
        assert_eq!(g.bytes_per_sector, 4096);
        assert!(matches!(g.fat_type, FatType::Fat32));
        assert_eq!(g.total_clusters, 300_000 - 632);
        // The same table read as 512-byte sectors holds an eighth of the
        // entries, too few for the clusters.
        let small = bpb_sector(512, 1, 32, 2, 0, 0, 0, 300_000, 300, 2, 1);
        assert!(matches!(
            parse_bpb_geometry(&small, 512, u64::MAX),
            Err(BpbError::BadGeometry)
        ));
    }

    #[test]
    fn encode_lfn_writes_utf16_code_units_not_utf8_bytes()
    {
        let mut out = [0u16; MAX_LFN_CHARS];
        // "é" is two UTF-8 bytes and one code unit; "😀" is four bytes and a
        // surrogate pair.
        let n = encode_lfn("caf\u{e9}\u{1f600}".as_bytes(), &mut out).expect("valid");
        assert_eq!(&out[..n], &[0x63, 0x61, 0x66, 0xE9, 0xD83D, 0xDE00]);
    }

    #[test]
    fn encode_lfn_round_trips_through_the_lfn_decoder()
    {
        let name = "r\u{e9}sum\u{e9} \u{4e2d}\u{6587}.txt";
        let mut units = [0u16; MAX_LFN_CHARS];
        let n = encode_lfn(name.as_bytes(), &mut units).expect("valid");
        let mut acc = LfnAccum::new();
        acc.chars[..n].copy_from_slice(&units[..n]);
        acc.len = n;
        let mut utf8 = [0u8; MAX_LFN_UTF8];
        let len = acc.assemble_utf8(&mut utf8).expect("decodes");
        assert_eq!(&utf8[..len], name.as_bytes());
    }

    #[test]
    fn encode_lfn_refuses_invalid_utf8_and_names_past_255_units()
    {
        let mut out = [0u16; MAX_LFN_CHARS];
        assert_eq!(encode_lfn(&[0x66, 0xFF], &mut out), None);
        // 255 three-byte characters fit (765 bytes); 128 surrogate pairs
        // (256 units) do not, although they are only 512 bytes.
        assert_eq!(
            encode_lfn("\u{4e2d}".repeat(255).as_bytes(), &mut out),
            Some(255)
        );
        assert_eq!(
            encode_lfn("\u{1f600}".repeat(128).as_bytes(), &mut out),
            None
        );
    }

    fn basis(base: &[u8], ext: &[u8]) -> [u8; 11]
    {
        let mut b = [b' '; 11];
        b[..base.len()].copy_from_slice(base);
        b[8..8 + ext.len()].copy_from_slice(ext);
        b
    }

    #[test]
    fn tailed_names_shorten_the_base_as_the_tail_grows()
    {
        let b = basis(b"LONGFILE", b"TXT");
        assert_eq!(compose_tailed_name(&b, 1), Some(*b"LONGFI~1TXT"));
        assert_eq!(compose_tailed_name(&b, 10), Some(*b"LONGF~10TXT"));
        assert_eq!(compose_tailed_name(&b, 999_999), Some(*b"L~999999TXT"));
        // A short base keeps every byte.
        assert_eq!(
            compose_tailed_name(&basis(b"AB", b""), 123),
            Some(*b"AB~123     ")
        );
        assert_eq!(compose_tailed_name(&b, 0), None);
        assert_eq!(compose_tailed_name(&b, 1_000_000), None);
    }

    #[test]
    fn tail_of_reads_back_only_names_of_the_same_basis()
    {
        let b = basis(b"LONGFILE", b"TXT");
        assert_eq!(tail_of(b"LONGF~10TXT", &b), Some(10));
        // Another extension, another basis, a leading zero, a plain name.
        assert_eq!(tail_of(b"LONGF~10DOC", &b), None);
        assert_eq!(tail_of(b"OTHER~10TXT", &b), None);
        assert_eq!(tail_of(b"LONGF~01TXT", &b), None);
        assert_eq!(tail_of(b"LONGFILETXT", &b), None);
    }

    #[test]
    fn a_set_with_every_covered_tail_used_has_no_free_tail()
    {
        let b = basis(b"X", b"");
        let mut used = TailSet::try_new().expect("heap");
        for t in 1..=DIR_ENTRIES_MAX + 1
        {
            used.note(&compose_tailed_name(&b, t).expect("in range"), &b);
        }
        assert_eq!(used.lowest_free(), None);
    }

    #[test]
    fn the_seventh_colliding_name_takes_the_lowest_free_tail()
    {
        // Tails 1 through 6 taken, and 8: the seventh colliding name gets ~7
        // where a six-tail scheme failed with NoSpace.
        let b = basis(b"REPORT", b"TXT");
        let mut used = TailSet::try_new().expect("heap");
        for t in [1, 2, 3, 4, 5, 6, 8]
        {
            used.note(&compose_tailed_name(&b, t).expect("in range"), &b);
        }
        assert_eq!(used.lowest_free(), Some(7));
    }

    #[test]
    fn a_full_directory_still_leaves_a_free_tail()
    {
        // Every entry a directory can hold carries one of the tails
        // 1..=65536: the next is free, within the set's range.
        let b = basis(b"X", b"");
        let mut used = TailSet::try_new().expect("heap");
        for t in 1..=DIR_ENTRIES_MAX
        {
            used.note(&compose_tailed_name(&b, t).expect("in range"), &b);
        }
        assert_eq!(used.lowest_free(), Some(DIR_ENTRIES_MAX + 1));
    }

    #[test]
    fn parse_bpb_geometry_accepts_exactly_the_clusters_a_fat32_table_holds()
    {
        // A 600-sector FAT32 table holds 76800 entries: clusters 2..76800.
        // data_start = 32 + 2*600 = 1232, one sector per cluster.
        let full = bpb_sector(512, 1, 32, 2, 0, 0, 0, 1232 + 76_798, 600, 2, 0);
        let g = parse_bpb_geometry(&full, 512, u64::MAX)
            .ok()
            .expect("FAT holds every cluster");
        assert_eq!(g.total_clusters, 76_798);
        let over = bpb_sector(512, 1, 32, 2, 0, 0, 0, 1232 + 76_799, 600, 2, 0);
        assert!(matches!(
            parse_bpb_geometry(&over, 512, u64::MAX),
            Err(BpbError::BadGeometry)
        ));
    }

    #[test]
    fn parse_bpb_geometry_accepts_exactly_the_clusters_a_fat16_table_holds()
    {
        // A 20-sector FAT16 table holds 5120 entries: clusters 2..5120.
        // data_start = 1 + 2*20 + 32 (512 root entries) = 73.
        let full = bpb_sector(512, 1, 1, 2, 512, 73 + 5118, 20, 0, 0, 0, 0);
        let g = parse_bpb_geometry(&full, 512, u64::MAX)
            .ok()
            .expect("FAT holds every cluster");
        assert!(matches!(g.fat_type, FatType::Fat16));
        assert_eq!(g.total_clusters, 5118);
        let over = bpb_sector(512, 1, 1, 2, 512, 73 + 5119, 20, 0, 0, 0, 0);
        assert!(matches!(
            parse_bpb_geometry(&over, 512, u64::MAX),
            Err(BpbError::BadGeometry)
        ));
    }

    #[test]
    fn parse_bpb_geometry_bounds_fat32_clusters_below_the_bad_cluster_marker()
    {
        // A FAT large enough for any count; data_start = 32 + 2*2097152.
        let fat = 2_097_152;
        let start = 32 + 2 * fat;
        let last = bpb_sector(512, 1, 32, 2, 0, 0, 0, start + 0x0FFF_FFF5, fat, 2, 0);
        assert!(parse_bpb_geometry(&last, 512, u64::MAX).is_ok());
        let marker = bpb_sector(512, 1, 32, 2, 0, 0, 0, start + 0x0FFF_FFF6, fat, 2, 0);
        assert!(matches!(
            parse_bpb_geometry(&marker, 512, u64::MAX),
            Err(BpbError::BadGeometry)
        ));
    }

    #[test]
    fn parse_bpb_geometry_rejects_a_fat32_root_outside_the_data_region()
    {
        let root_one = bpb_sector(512, 1, 32, 2, 0, 0, 0, 300_000, 2400, 1, 1);
        assert!(matches!(
            parse_bpb_geometry(&root_one, 512, u64::MAX),
            Err(BpbError::BadGeometry)
        ));
    }

    #[test]
    fn parse_bpb_geometry_treats_an_fsinfo_sector_past_the_reserved_region_as_absent()
    {
        // 32 reserved sectors: sector 32 is the first FAT sector.
        let g = parse_bpb_geometry(&fat32_sector(32), 512, u64::MAX)
            .ok()
            .expect("valid FAT32");
        assert_eq!(g.fsinfo_sector, None);
    }

    #[test]
    fn parse_bpb_geometry_rejects_zero_fats_or_reserved_sectors()
    {
        let no_fats = bpb_sector(512, 4, 1, 0, 512, 8192, 20, 0, 0, 0, 0);
        assert!(matches!(
            parse_bpb_geometry(&no_fats, 512, u64::MAX),
            Err(BpbError::BadGeometry)
        ));
        let no_reserved = bpb_sector(512, 4, 0, 2, 512, 8192, 20, 0, 0, 0, 0);
        assert!(matches!(
            parse_bpb_geometry(&no_reserved, 512, u64::MAX),
            Err(BpbError::BadGeometry)
        ));
    }

    #[test]
    fn parse_bpb_geometry_rejects_an_overflowing_data_start()
    {
        let huge_fat = bpb_sector(512, 1, 32, 2, 0, 0, 0, u32::MAX, u32::MAX, 2, 0);
        assert!(matches!(
            parse_bpb_geometry(&huge_fat, 512, u64::MAX),
            Err(BpbError::BadGeometry)
        ));
    }

    #[test]
    fn cluster_to_sector_saturates_instead_of_overflowing()
    {
        // A corrupt 0x0FFF_FFF0 entry times 64 sectors per cluster overflows u32.
        assert_eq!(cluster_to_sector(100, 64, 0x0FFF_FFF0), u32::MAX);
    }

    #[test]
    fn is_data_cluster_bounds_the_data_region()
    {
        assert!(!is_data_cluster(1, 10));
        assert!(is_data_cluster(2, 10));
        assert!(is_data_cluster(11, 10));
        assert!(!is_data_cluster(12, 10));
    }

    #[test]
    fn cluster_to_sector_clamps_reserved_clusters_to_data_start()
    {
        // Clusters 0 and 1 are reserved: clamp to data_start, never underflow.
        assert_eq!(cluster_to_sector(100, 8, 0), 100);
        assert_eq!(cluster_to_sector(100, 8, 1), 100);
    }

    #[test]
    fn fat_entry_location_finds_the_sector_and_offset_of_each_width()
    {
        // FAT16: cluster 300 is byte 600, sector 1 offset 88 of 512-byte sectors.
        assert_eq!(
            fat_entry_location(FatType::Fat16, 4, 512, 300),
            Some((5, 88))
        );
        // FAT32: cluster 300 is byte 1200, sector 2 offset 176.
        assert_eq!(
            fat_entry_location(FatType::Fat32, 32, 512, 300),
            Some((34, 176))
        );
        assert_eq!(
            fat_entry_location(FatType::Fat32, 32, 4096, 1025),
            Some((33, 4))
        );
    }

    #[test]
    fn fat_entry_location_refuses_overflow_and_a_zero_sector_size()
    {
        assert_eq!(fat_entry_location(FatType::Fat32, 32, 512, u32::MAX), None);
        assert_eq!(fat_entry_location(FatType::Fat16, 4, 0, 2), None);
        // The entry's byte offset fits, the sector number does not.
        assert_eq!(
            fat_entry_location(FatType::Fat32, u16::MAX, 1, 0x3FFF_FFFF),
            None
        );
    }

    #[test]
    fn fat_entries_round_trip_and_fat32_keeps_its_reserved_bits()
    {
        let mut sector = [0u8; 512];
        sector[8..12].copy_from_slice(&0xA000_0005u32.to_le_bytes());
        assert_eq!(read_fat_entry(&sector, FatType::Fat32, 8), Some(5));
        assert_eq!(
            write_fat_entry(&mut sector, FatType::Fat32, 8, 0xFFFF_FFFF),
            Some(())
        );
        assert_eq!(sector[8..12], 0xAFFF_FFFFu32.to_le_bytes());
        assert_eq!(
            read_fat_entry(&sector, FatType::Fat32, 8),
            Some(0x0FFF_FFFF)
        );

        assert_eq!(
            write_fat_entry(&mut sector, FatType::Fat16, 2, 0x1_FFF7),
            Some(())
        );
        assert_eq!(sector[2..4], [0xF7, 0xFF]);
        assert_eq!(read_fat_entry(&sector, FatType::Fat16, 2), Some(0xFFF7));
    }

    #[test]
    fn a_fat_entry_past_its_sector_is_neither_read_nor_written()
    {
        let mut sector = [0xAAu8; 512];
        assert_eq!(read_fat_entry(&sector, FatType::Fat32, 510), None);
        assert_eq!(read_fat_entry(&sector, FatType::Fat16, 512), None);
        assert_eq!(read_fat_entry(&sector, FatType::Fat16, usize::MAX), None);
        assert_eq!(write_fat_entry(&mut sector, FatType::Fat32, 509, 0), None);
        assert_eq!(write_fat_entry(&mut sector, FatType::Fat16, 511, 0), None);
        assert!(sector.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn file_position_splits_an_offset_into_cluster_sector_and_byte()
    {
        // 4 sectors of 512 bytes per cluster: byte 5000 is in cluster 2
        // (bytes 4096..6144), sector 1 of it (4608..5120), byte 392.
        assert_eq!(
            file_position(5000, 4, 512),
            Some(FilePosition {
                cluster_index: 2,
                left_in_cluster: 1144,
                sector_in_cluster: 1,
                offset_in_sector: 392,
                left_in_sector: 120,
            })
        );
        assert_eq!(
            file_position(0, 1, 4096),
            Some(FilePosition {
                cluster_index: 0,
                left_in_cluster: 4096,
                sector_in_cluster: 0,
                offset_in_sector: 0,
                left_in_sector: 4096,
            })
        );
        // The largest offset a FAT file reaches, on the largest cluster.
        assert_eq!(
            file_position(u64::from(u32::MAX), 255, 4096),
            Some(FilePosition {
                cluster_index: 4112,
                left_in_cluster: 978_945,
                sector_in_cluster: 15,
                offset_in_sector: 4095,
                left_in_sector: 1,
            })
        );
    }

    #[test]
    fn file_position_refuses_a_zero_geometry()
    {
        assert_eq!(file_position(10, 0, 512), None);
        assert_eq!(file_position(10, 8, 0), None);
    }

    /// The share of the sector holding `at` on a volume of one 512-byte
    /// sector per cluster.
    fn share(at: u64, offset: u64, end: u64, old_size: u64) -> Option<SectorWrite>
    {
        sector_write(&file_position(at, 1, 512)?, at, offset, end, old_size)
    }

    #[test]
    fn sector_write_zero_fills_the_gap_before_the_payload()
    {
        // A 23-byte file written at 1031..1035: its first sector keeps bytes
        // 0..23 and zeros the rest, the next is all zeros, the third holds
        // 7 zeros then the payload; none past the first is read.
        let first = SectorWrite {
            zeros: 489,
            data: 0,
            read_first: true,
        };
        assert_eq!(share(23, 1031, 1035, 23), Some(first));
        let gap = SectorWrite {
            zeros: 512,
            data: 0,
            read_first: false,
        };
        assert_eq!(share(512, 1031, 1035, 23), Some(gap));
        let last = SectorWrite {
            zeros: 7,
            data: 4,
            read_first: false,
        };
        assert_eq!(share(1024, 1031, 1035, 23), Some(last));
    }

    #[test]
    fn sector_write_reads_only_a_sector_holding_bytes_it_keeps()
    {
        // In place, below the old size on both sides.
        let inside = SectorWrite {
            zeros: 0,
            data: 10,
            read_first: true,
        };
        assert_eq!(share(100, 100, 110, 400), Some(inside));
        // From the sector's start, the old size inside the share.
        let over_end = SectorWrite {
            zeros: 0,
            data: 10,
            read_first: false,
        };
        assert_eq!(share(512, 512, 522, 520), Some(over_end));
        // From the sector's start, the old size past the share.
        let keeps_tail = SectorWrite {
            zeros: 0,
            data: 10,
            read_first: true,
        };
        assert_eq!(share(512, 512, 522, 600), Some(keeps_tail));
        // The whole sector.
        let whole = SectorWrite {
            zeros: 0,
            data: 512,
            read_first: false,
        };
        assert_eq!(share(512, 512, 2048, 4096), Some(whole));
        // An append at the old size, mid-sector, keeps the bytes before it.
        let append = SectorWrite {
            zeros: 0,
            data: 5,
            read_first: true,
        };
        assert_eq!(share(700, 700, 705, 700), Some(append));
    }

    #[test]
    fn sector_write_refuses_an_empty_share_or_a_misplaced_position()
    {
        assert_eq!(share(100, 100, 100, 0), None);
        assert_eq!(share(200, 100, 150, 0), None);
        let pos = file_position(600, 1, 512).unwrap();
        assert_eq!(sector_write(&pos, 50, 50, 60, 0), None);
    }

    #[test]
    fn packed_lfn_slots_decode_back_to_the_name()
    {
        // 27 units: two full slots and one holding a single unit, its
        // terminator, and padding.
        let name = "abcdefghijklmnopqrstuvw.txt";
        let sfn = *b"ABCDEF~1TXT";
        let chksum = lfn_checksum(&sfn);
        let mut units = [0u16; MAX_LFN_CHARS];
        let n = encode_lfn(name.as_bytes(), &mut units).expect("valid");
        let count = u8::try_from(n.div_ceil(13)).expect("fits");
        let mut acc = LfnAccum::new();
        for seq in (1..=count).rev()
        {
            let slot = pack_lfn_slot(seq, seq == count, chksum, &units[..n]).expect("in range");
            assert_eq!(slot[11], ATTR_LFN);
            acc.add_lfn_entry(&slot);
        }
        assert!(acc.validate(&sfn));
        let mut out = [0u8; MAX_LFN_UTF8];
        let len = acc.assemble_utf8(&mut out).expect("decodes");
        assert_eq!(&out[..len], name.as_bytes());

        let last = pack_lfn_slot(count, true, chksum, &units[..n]).expect("in range");
        assert_eq!(last[0], count | 0x40);
        // Unit 26 (`t`), then the terminator, then padding.
        assert_eq!(last[1..7], [b't', 0, 0, 0, 0xFF, 0xFF]);
        assert_eq!(last[30..32], [0xFF, 0xFF]);
    }

    #[test]
    fn pack_lfn_slot_refuses_a_sequence_outside_the_run()
    {
        assert_eq!(pack_lfn_slot(0, true, 0, &[0x41]), None);
        assert!(pack_lfn_slot(20, true, 0, &[0x41]).is_some());
        assert_eq!(pack_lfn_slot(21, true, 0, &[0x41]), None);
    }

    #[test]
    fn lfn_checksum_computes_rotate_carry_over_known_8_3_name()
    {
        // The 8.3 form of README.TXT. The carry-rotate (>>1 with the lsb
        // folded into bit 7) and the wrapping add both engage partway through,
        // so a plain >>1 or a non-wrapping add would yield a different byte.
        assert_eq!(lfn_checksum(b"README  TXT"), 0x73);
    }

    #[test]
    fn parse_dir_entry_decodes_32_byte_record_with_split_cluster()
    {
        let mut raw = [0u8; 32];
        raw[..11].copy_from_slice(b"FILE    TXT");
        raw[11] = 0x20; // archive attr
        raw[12] = 0x08; // NT base-lowercase flag
        raw[20..22].copy_from_slice(&0x0012u16.to_le_bytes()); // cluster hi
        raw[26..28].copy_from_slice(&0x3456u16.to_le_bytes()); // cluster lo
        raw[28..32].copy_from_slice(&4096u32.to_le_bytes()); // size

        let e = parse_dir_entry(&raw).expect("live entry");
        assert_eq!(&e.name, b"FILE    TXT");
        assert_eq!(e.attr, 0x20);
        assert_eq!(e.nt_case, 0x08);
        // hi<<16 | lo joins the split cluster fields.
        assert_eq!(e.cluster, 0x0012_3456);
        assert_eq!(e.size, 4096);
        assert_eq!(e.lfn_len, 0);
    }

    #[test]
    fn display_name_of_an_8_3_entry_honours_nt_case_bits_and_drops_padding()
    {
        let mut out = [0u8; MAX_LFN_UTF8];
        let both = DirEntry::from_83(*b"BOOT    CNF", 0x18, 0, 0, 0);
        let len = both.write_display_name(&mut out, MAX_LFN_UTF8);
        assert_eq!(&out[..len], b"boot.cnf");
        let ext_only = DirEntry::from_83(*b"BOOT    CNF", 0x10, 0, 0, 0);
        let len = ext_only.write_display_name(&mut out, MAX_LFN_UTF8);
        assert_eq!(&out[..len], b"BOOT.cnf");
        let no_ext = DirEntry::from_83(*b"README     ", 0, 0, 0, 0);
        let len = no_ext.write_display_name(&mut out, MAX_LFN_UTF8);
        assert_eq!(&out[..len], b"README");
    }

    #[test]
    fn display_name_stops_at_the_end_of_a_short_buffer()
    {
        let entry = DirEntry::from_83(*b"BOOT    CNF", 0, 0, 0, 0);
        let mut out = [0u8; 5];
        assert_eq!(entry.write_display_name(&mut out, MAX_LFN_UTF8), 5);
        assert_eq!(&out, b"BOOT.");
    }

    #[test]
    fn display_name_with_a_long_name_length_past_its_buffer_writes_the_buffer()
    {
        let mut entry = DirEntry::from_83(*b"X          ", 0, 0, 0, 0);
        entry.lfn = [b'a'; MAX_LFN_UTF8];
        entry.lfn_len = u16::MAX;
        let mut out = [0u8; MAX_LFN_UTF8 + 1];
        // No name limit, so the long-name path runs with its corrupt length.
        assert_eq!(entry.write_display_name(&mut out, usize::MAX), MAX_LFN_UTF8);
        assert!(out[..MAX_LFN_UTF8].iter().all(|&b| b == b'a'));
    }

    #[test]
    fn parse_dir_entry_returns_none_for_each_sentinel()
    {
        let mut end = [0x20u8; 32];
        end[0] = 0x00; // end-of-directory
        assert!(parse_dir_entry(&end).is_none());

        let mut deleted = [0x20u8; 32];
        deleted[0] = 0xE5; // deleted
        assert!(parse_dir_entry(&deleted).is_none());

        let mut lfn = [0x20u8; 32];
        lfn[0] = 0x41;
        lfn[11] = 0x0F; // LFN attr
        assert!(parse_dir_entry(&lfn).is_none());

        let mut label = [0x20u8; 32];
        label[..11].copy_from_slice(b"SERAPH     ");
        label[11] = 0x08 | 0x20; // volume label, archive bit set
        assert!(parse_dir_entry(&label).is_none());
    }

    #[test]
    fn name_matches_folds_case_and_pads_8_3()
    {
        // On-disk 8.3 is space-padded uppercase; a lowercase dotted component
        // must fold and pad to match.
        assert!(name_matches(b"FILE    TXT", b"file.txt"));
        assert!(name_matches(b"README     ", b"readme"));
        assert!(!name_matches(b"FILE    TXT", b"other.txt"));
    }

    #[test]
    fn a_component_longer_than_8_3_matches_no_short_name()
    {
        // A long name names its entry by the long name alone: its prefix
        // never matches another entry's short name.
        assert!(!name_matches(b"LONGNAMEEXT", b"longnamethatislong.extra"));
        assert!(!name_matches(b"FOOBAR~1   ", b"foobar~1 extra"));
        assert!(!name_matches(b"FILE    TXT", b"file.txta"));
        // The longest short-name spelling still matches.
        assert!(name_matches(b"LONGNAMEEXT", b"longname.ext"));
    }

    #[test]
    fn lfn_run_assembles_utf8_name_and_validates_against_8_3()
    {
        // 8.3 entry the run trails; its checksum gates the run.
        let sfn = b"FILE    TXT";
        let chk = lfn_checksum(sfn);

        // Single-entry run (seq 1, last-of-run flag 0x40) spelling "file.txt".
        let name = "file.txt";
        let mut entry = [0u8; 32];
        entry[0] = 0x40 | 0x01; // last-of-run, seq 1
        entry[11] = 0x0F; // LFN attr
        entry[13] = chk;
        let offsets: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        let units: Vec<u16> = name.encode_utf16().collect();
        for (i, &off) in offsets.iter().enumerate()
        {
            let ch = units.get(i).copied().unwrap_or(0x0000);
            entry[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }

        let mut acc = LfnAccum::new();
        acc.add_lfn_entry(&entry);
        assert!(acc.validate(sfn));

        let mut out = [0u8; MAX_LFN_UTF8];
        let len = acc.assemble_utf8(&mut out).expect("valid UTF-8");
        assert_eq!(&out[..len], name.as_bytes());
        assert!(acc.matches(b"FILE.TXT")); // case-insensitive
    }

    #[test]
    fn lfn_run_rejected_when_checksum_mismatches_sfn()
    {
        // A complete run whose chksum byte does not match lfn_checksum(sfn)
        // fails validation, forcing the 8.3 fallback.
        let sfn = b"FILE    TXT";
        let mut entry = [0u8; 32];
        entry[0] = 0x40 | 0x01;
        entry[11] = 0x0F;
        entry[13] = lfn_checksum(sfn).wrapping_add(1); // wrong checksum
        entry[1..3].copy_from_slice(&u16::from(b'f').to_le_bytes());

        let mut acc = LfnAccum::new();
        acc.add_lfn_entry(&entry);
        assert!(!acc.validate(sfn));
    }

    #[test]
    fn assemble_utf8_rejects_unpaired_high_surrogate()
    {
        // A high surrogate with no following low surrogate is malformed.
        let sfn = b"X          ";
        let mut entry = [0u8; 32];
        entry[0] = 0x40 | 0x01;
        entry[11] = 0x0F;
        entry[13] = lfn_checksum(sfn);
        entry[1..3].copy_from_slice(&0xD800u16.to_le_bytes()); // lone high surrogate

        let mut acc = LfnAccum::new();
        acc.add_lfn_entry(&entry);
        let mut out = [0u8; MAX_LFN_UTF8];
        assert!(acc.assemble_utf8(&mut out).is_none());
    }

    #[test]
    fn lfn_run_of_maximum_length_assembles_all_255_chars()
    {
        // A 20-slot run spans 260 positions but holds at most 255 chars; the
        // assembled name must stop at 255 rather than read past the buffer.
        let sfn = b"AAAAAA~1   ";
        let long = "a".repeat(MAX_LFN_CHARS);
        let mut acc = LfnAccum::new();
        for slot in &lfn_entry_slots(&long, sfn, lfn_checksum(sfn))[..20]
        {
            acc.add_lfn_entry(slot);
        }
        assert!(acc.validate(sfn));
        let mut out = [0u8; MAX_LFN_UTF8];
        assert_eq!(acc.assemble_utf8(&mut out), Some(MAX_LFN_CHARS));
        assert!(acc.matches(long.as_bytes()));
    }

    /// Directory slots for `long` stored under the 8.3 name `sfn`: the LFN
    /// run in on-disk (reverse-sequence) order, then the 8.3 entry, every
    /// LFN slot carrying `chksum`.
    fn lfn_entry_slots(long: &str, sfn: &[u8; 11], chksum: u8) -> Vec<[u8; 32]>
    {
        let offsets: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        let units: Vec<u16> = long.encode_utf16().collect();
        let count = units.len().div_ceil(13);
        let mut slots = Vec::new();
        for seq in (1..=count).rev()
        {
            let mut slot = [0u8; 32];
            slot[0] = u8::try_from(seq).expect("seq fits") | if seq == count { 0x40 } else { 0 };
            slot[11] = 0x0F;
            slot[13] = chksum;
            for (i, &off) in offsets.iter().enumerate()
            {
                let ch = units.get((seq - 1) * 13 + i).copied().unwrap_or(0x0000);
                slot[off..off + 2].copy_from_slice(&ch.to_le_bytes());
            }
            slots.push(slot);
        }
        let mut entry = [0u8; 32];
        entry[..11].copy_from_slice(sfn);
        entry[11] = 0x20;
        entry[26..28].copy_from_slice(&7u16.to_le_bytes());
        slots.push(entry);
        slots
    }

    /// Feed `slots` (each located at its index) to a removal scan for `name`;
    /// returns the step that ended the scan and the scan's run.
    fn scan_for_remove(slots: &[[u8; 32]], name: &[u8]) -> (RemoveStep, Vec<usize>)
    {
        let mut scan = RemoveRunScan::new();
        for (i, slot) in slots.iter().enumerate()
        {
            let step = scan.step(slot, i, name);
            if !matches!(step, RemoveStep::Continue)
            {
                return (step, scan.run().to_vec());
            }
        }
        (RemoveStep::Continue, Vec::new())
    }

    fn found_run(slots: &[[u8; 32]], name: &[u8]) -> Vec<usize>
    {
        let (step, run) = scan_for_remove(slots, name);
        assert!(matches!(step, RemoveStep::Found { cluster: 7 }));
        run
    }

    #[test]
    fn remove_by_short_alias_covers_the_validated_lfn_slots()
    {
        // Removing by alias must delete the long name too, or its LFN slots
        // stay live as an orphan run.
        let sfn = b"LONGFI~1TXT";
        let slots = lfn_entry_slots("LongFileName.txt", sfn, lfn_checksum(sfn));
        let run = found_run(&slots, b"longfi~1.txt");
        assert_eq!(run, vec![0, 1, 2]);
    }

    #[test]
    fn remove_run_of_a_plain_8_3_entry_is_its_one_slot()
    {
        // The removal marks exactly the run deleted; any slot beyond the
        // entry's own would overwrite an unrelated on-disk byte.
        let mut other = [0u8; 32];
        other[..11].copy_from_slice(b"OTHER   TXT");
        other[11] = 0x20;
        let mut entry = other;
        entry[..11].copy_from_slice(b"FILE    TXT");
        entry[26..28].copy_from_slice(&7u16.to_le_bytes());
        let run = found_run(&[other, entry, [0u8; 32]], b"file.txt");
        assert_eq!(run, vec![1]);
    }

    #[test]
    fn remove_by_long_name_covers_the_lfn_and_8_3_slots()
    {
        let sfn = b"LONGFI~1TXT";
        let slots = lfn_entry_slots("LongFileName.txt", sfn, lfn_checksum(sfn));
        let run = found_run(&slots, b"longfilename.TXT");
        assert_eq!(run, vec![0, 1, 2]);
    }

    #[test]
    fn remove_run_excludes_lfn_slots_whose_checksum_mismatches()
    {
        // LFN slots that do not belong to the 8.3 entry are not deleted with it.
        let sfn = b"LONGFI~1TXT";
        let slots = lfn_entry_slots("LongFileName.txt", sfn, lfn_checksum(sfn) ^ 1);
        let run = found_run(&slots, b"LONGFI~1.TXT");
        assert_eq!(run, vec![2]);
    }

    #[test]
    fn remove_run_excludes_lfn_slots_separated_by_a_deleted_slot()
    {
        let sfn = b"LONGFI~1TXT";
        let mut slots = lfn_entry_slots("LongFileName.txt", sfn, lfn_checksum(sfn));
        let mut deleted = [0u8; 32];
        deleted[0] = 0xE5;
        slots.insert(2, deleted);
        let run = found_run(&slots, b"LONGFI~1.TXT");
        assert_eq!(run, vec![3]);
    }

    #[test]
    fn remove_run_drops_orphan_slots_before_a_maximum_length_run()
    {
        // An orphan slot ahead of a 20-slot run must neither join the run nor
        // push the 8.3 slot past the end of it.
        let sfn = b"AAAAAA~1   ";
        let long = "a".repeat(MAX_LFN_CHARS);
        let mut slots = lfn_entry_slots(&long, sfn, lfn_checksum(sfn));
        let mut orphan = slots[0];
        orphan[13] ^= 1;
        slots.insert(0, orphan);
        let run = found_run(&slots, b"AAAAAA~1");
        assert_eq!(run, (1..=MAX_SLOT_RUN).collect::<Vec<_>>());
    }

    #[test]
    fn free_run_continues_past_the_end_of_directory_marker()
    {
        // Two used entries, the 0x00 marker at slot 2, then stale bytes the
        // specification declares free: a 3-slot run starts at the marker.
        let mut scan = FreeRunScan::<usize>::new(3);
        assert!(!scan.step(b'A', 0));
        assert!(!scan.step(b'B', 1));
        assert!(!scan.step(0x00, 2));
        assert!(scan.past_end());
        assert!(!scan.step(b'Z', 3));
        // The run is complete, and the slot after it, whatever it holds,
        // takes the new end-of-directory marker.
        assert!(!scan.step(b'Q', 4));
        assert!(scan.run_complete());
        assert_eq!(scan.end_marker(), None);
        assert!(scan.step(b'R', 5));
        assert_eq!(scan.run(), &[2, 3, 4]);
        assert_eq!(scan.end_marker(), Some(5));
        assert!(scan.step(b'S', 6));
        assert_eq!(scan.end_marker(), Some(5));
    }

    #[test]
    fn free_run_before_the_marker_needs_no_new_marker()
    {
        // A run of deleted slots that ends before the 0x00 marker is
        // followed by that marker still, so the scan ends with the run.
        let mut scan = FreeRunScan::<usize>::new(2);
        assert!(!scan.step(0xE5, 0));
        assert!(scan.step(0xE5, 1));
        assert!(!scan.past_end());
        assert_eq!(scan.end_marker(), None);
    }

    #[test]
    fn free_run_that_ends_with_the_directory_has_no_marker_slot()
    {
        // The run fills the directory's last slots: complete, with no slot
        // after it to mark.
        let mut scan = FreeRunScan::<usize>::new(2);
        assert!(!scan.step(b'A', 0));
        assert!(!scan.step(0x00, 1));
        assert!(!scan.step(0x00, 2));
        assert!(scan.run_complete());
        assert_eq!(scan.run(), &[1, 2]);
        assert_eq!(scan.end_marker(), None);
    }

    #[test]
    fn free_run_step_after_a_complete_run_keeps_the_run()
    {
        // A step past a full-length run must not index past the slot array.
        let mut scan = FreeRunScan::<usize>::new(MAX_SLOT_RUN);
        for i in 0..MAX_SLOT_RUN
        {
            scan.step(0xE5, i);
        }
        assert!(scan.step(0xE5, MAX_SLOT_RUN));
        assert_eq!(scan.run().len(), MAX_SLOT_RUN);
        assert_eq!(scan.run().last(), Some(&(MAX_SLOT_RUN - 1)));
    }

    #[test]
    fn free_run_restarts_on_a_used_slot()
    {
        let mut scan = FreeRunScan::<usize>::new(2);
        assert!(!scan.step(0xE5, 0));
        assert!(!scan.step(b'A', 1));
        assert!(!scan.step(0xE5, 2));
        assert!(scan.step(0xE5, 3));
        assert_eq!(scan.run(), &[2, 3]);
    }

    #[test]
    fn remove_scan_stops_at_end_of_directory_without_a_match()
    {
        let sfn = b"OTHER   TXT";
        let mut slots = lfn_entry_slots("Other file.txt", sfn, lfn_checksum(sfn));
        slots.push([0u8; 32]);
        assert!(matches!(
            scan_for_remove(&slots, b"missing.txt").0,
            RemoveStep::EndOfDir
        ));
    }
    #[test]
    fn parse_bpb_geometry_refuses_a_volume_larger_than_its_partition()
    {
        // fat16_sector declares 8192 sectors: a partition of 8192 holds it,
        // one of 8191 does not, so the data region would pass its end.
        let s = fat16_sector();
        let g = parse_bpb_geometry(&s, 512, 8192)
            .ok()
            .expect("volume fits its partition");
        assert_eq!(g.total_sectors, 8192);
        assert!(matches!(
            parse_bpb_geometry(&s, 512, 8191),
            Err(BpbError::BadGeometry)
        ));
        // The 32-bit count is held to the partition the same way.
        let big = fat32_sector(1);
        let sectors = u64::from(
            parse_bpb_geometry(&big, 512, u64::MAX)
                .ok()
                .expect("FAT32")
                .total_sectors,
        );
        assert!(parse_bpb_geometry(&big, 512, sectors).is_ok());
        assert!(matches!(
            parse_bpb_geometry(&big, 512, sectors - 1),
            Err(BpbError::BadGeometry)
        ));
    }

    #[test]
    fn parse_bpb_geometry_gives_a_fat16_volume_no_root_cluster()
    {
        // On FAT16, bytes 44..48 are the volume label: a label that spells a
        // data-region cluster number must not become a root cluster.
        let mut s = fat16_sector();
        s[44..48].copy_from_slice(&5u32.to_le_bytes());
        let g = parse_bpb_geometry(&s, 512, u64::MAX).ok().expect("FAT16");
        assert!(matches!(g.fat_type, FatType::Fat16));
        assert_eq!(g.root_cluster, 0);
    }

    #[test]
    fn display_name_past_the_name_limit_falls_back_to_the_short_name()
    {
        // 90 CJK characters take 270 UTF-8 bytes: past a 255-byte name, so
        // the entry is listed under its 8.3 alias, which a lookup accepts.
        let long = "\u{6587}".repeat(90);
        let sfn = b"6587~1     ";
        let mut acc = LfnAccum::new();
        let slots = lfn_entry_slots(&long, sfn, lfn_checksum(sfn));
        let (lfn_slots, short) = slots.split_at(slots.len() - 1);
        for slot in lfn_slots
        {
            acc.add_lfn_entry(slot);
        }
        assert!(acc.validate(sfn));
        let mut entry = parse_dir_entry(&short[0]).expect("8.3 entry");
        let len = acc.assemble_utf8(&mut entry.lfn).expect("valid UTF-8");
        entry.lfn_len = u16::try_from(len).expect("fits");
        assert_eq!(len, 270);
        let mut out = [0u8; MAX_LFN_UTF8];
        let shown = entry.write_display_name(&mut out, 255);
        assert_eq!(&out[..shown], b"6587~1");
        // Under a limit the long name fits, it is the one shown.
        let shown = entry.write_display_name(&mut out, 270);
        assert_eq!(&out[..shown], long.as_bytes());
    }

    #[test]
    fn dir_chain_limit_is_the_directory_size_in_clusters_within_the_volume()
    {
        // 2 MiB of entries: 4096 clusters of 512 bytes, 32 of 64 KiB.
        assert_eq!(dir_chain_limit(0x0FFF_FFF5, 1, 512), 4096);
        assert_eq!(dir_chain_limit(0x0FFF_FFF5, 128, 512), 32);
        // A cluster size that does not divide 2 MiB rounds up.
        assert_eq!(dir_chain_limit(1_000_000, 3, 512), 1366);
        // Never more than the volume holds.
        assert_eq!(dir_chain_limit(10, 1, 512), 10);
        assert_eq!(dir_chain_limit(100, 0, 512), 0);
    }

    /// Every checked-in input of fuzz/fat/ of the `kinds` given (`seeds`,
    /// `regressions`).
    fn fuzz_inputs(kinds: &[&str]) -> Vec<Vec<u8>>
    {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/fat");
        let mut inputs = Vec::new();
        for kind in kinds
        {
            let Ok(entries) = std::fs::read_dir(dir.join(kind))
            else
            {
                continue;
            };
            for entry in entries
            {
                inputs.push(std::fs::read(entry.unwrap().path()).unwrap());
            }
        }
        inputs
    }

    // Defect caught: a parser change that breaks its contract on an input
    // the fuzz target once found or started from; `cargo xtask test` replays
    // every checked-in input of fuzz/fat/ on each change.
    #[test]
    fn every_checked_in_fuzz_input_holds_the_parser_contract()
    {
        let inputs = fuzz_inputs(&["seeds", "regressions"]);
        assert!(!inputs.is_empty(), "no checked-in input under fuzz/fat");
        for input in &inputs
        {
            property::fat_holds(input);
        }
    }

    // Defect caught: seeds that no longer reach an accepted volume of each
    // type and size, a volume refused for its cluster size, or a valid long
    // name, so the search starts from inputs that stop at the first refusal.
    #[test]
    fn the_seeds_reach_both_fat_types_and_a_valid_long_name()
    {
        let seeds = fuzz_inputs(&["seeds"]);
        let accepted = |fat32: bool, size: u32| {
            seeds.iter().any(|seed| {
                parse_bpb_geometry(seed, size, u64::MAX)
                    .is_ok_and(|g| matches!(g.fat_type, FatType::Fat32) == fat32)
            })
        };
        assert!(accepted(false, 512), "no FAT16 seed");
        assert!(accepted(true, 512), "no FAT32 seed");
        assert!(accepted(true, 4096), "no 4096-byte-sector seed");
        assert!(
            seeds.iter().any(|seed| seed.get(13) == Some(&3)
                && matches!(
                    parse_bpb_geometry(seed, 512, u64::MAX),
                    Err(BpbError::BadGeometry)
                )),
            "no seed refused for a cluster size that is not a power of two"
        );
        let long_name = seeds.iter().any(|seed| {
            let mut acc = LfnAccum::new();
            seed.as_chunks::<32>().0.iter().any(|raw| {
                if raw[11] == ATTR_LFN
                {
                    acc.add_lfn_entry(raw);
                    return false;
                }
                let valid = parse_dir_entry(raw).is_some_and(|e| acc.validate(&e.name));
                acc.reset();
                valid
            })
        });
        assert!(long_name, "no seed holds a valid long-name run");
    }

    // Defect caught: a name holding U+0000 or U+FFFF, whose code units a
    // long name's slots take as its end, written as a long name that reads
    // back cut short at that character.
    #[test]
    fn encode_lfn_refuses_a_character_that_ends_a_long_name()
    {
        let mut units = [0u16; MAX_LFN_CHARS];
        assert_eq!(encode_lfn("a\u{FFFF}b".as_bytes(), &mut units), None);
        assert_eq!(encode_lfn(b"a\0b", &mut units), None);
        assert_eq!(encode_lfn("a\u{FFFE}b".as_bytes(), &mut units), Some(3));
    }
}
