// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/src/bpb.rs

//! BIOS Parameter Block parsing and FAT filesystem state.
//!
//! Reads sector 0 of a FAT partition, validates the boot signature, and
//! populates a [`FatState`] with geometry fields needed by the rest of the
//! driver (cluster size, FAT start, data region start, FAT type).

// MAX_SECTOR_SIZE and FatType are defined by the pure, host-testable fat_parse
// crate; the geometry/state machine and block I/O below consume them.
pub use fat_parse::{FatType, FilePosition, MAX_SECTOR_SIZE};

use crate::alloc::FatError;

/// A zeroed heap buffer of [`MAX_SECTOR_SIZE`] bytes, which holds a sector of
/// any size the driver mounts; a sector occupies its first
/// [`FatState::sector_bytes`]. On the heap to keep the write-path frames
/// within the default thread stack when release LTO inlines the nested
/// helpers.
///
/// # Errors
/// [`FatError::Io`] when the heap cannot hold the buffer; the request fails
/// as an I/O error would.
pub fn sector_buffer() -> Result<Box<[u8; MAX_SECTOR_SIZE]>, FatError>
{
    let mut buf = Vec::new();
    buf.try_reserve_exact(MAX_SECTOR_SIZE)
        .map_err(|_| FatError::Io)?;
    buf.resize(MAX_SECTOR_SIZE, 0);
    // The vector holds exactly MAX_SECTOR_SIZE bytes, so the conversion
    // never fails.
    buf.into_boxed_slice().try_into().map_err(|_| FatError::Io)
}

/// Parsed FAT filesystem geometry and cached FAT sector.
pub struct FatState
{
    pub fat_type: FatType,
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    /// Root directory entry count (FAT16 only).
    pub root_entry_count: u16,
    /// Sectors per FAT table.
    pub fat_size: u32,
    /// Root cluster number (FAT32 only).
    pub root_cluster: u32,
    /// First sector of the data region.
    pub data_start_sector: u32,
    /// Cached FAT sector number (avoids re-reads for sequential access).
    pub cached_fat_sector: u32,
    /// Cached FAT sector data; the first `bytes_per_sector` bytes hold the
    /// sector.
    pub cached_fat_data: [u8; MAX_SECTOR_SIZE],
    /// Total cluster count (data-region size / cluster size). Used by
    /// the cluster allocator to bound its FAT scan and by mount-time
    /// validation. `cached_fat_sector` and the FAT array index range
    /// `[2..2 + total_clusters)`.
    pub total_clusters: u32,
    /// `FSInfo` sector LBA (FAT32 only; `u32::MAX` sentinel otherwise).
    /// Loaded from BPB offset 48 by `parse_bpb` when the detected type
    /// is FAT32. The `FSInfo` content (free count, next-free hint) is
    /// loaded separately by the allocator at mount, since `parse_bpb`
    /// does not have block-device access.
    pub fsinfo_sector: u32,
    /// FAT32 advisory hint: next cluster the allocator should consider
    /// for a free-cluster search. Microsoft spec §6 marks this field
    /// advisory; the allocator revalidates by reading the FAT entry. A
    /// `u32::MAX` sentinel forces a scan from cluster 2.
    pub next_free_hint: u32,
    /// FAT32 advisory free-cluster count. `u32::MAX` sentinel means
    /// unknown. Maintained best-effort by the allocator.
    pub free_count_hint: u32,
}

impl FatState
{
    /// Create a default state (pre-mount).
    pub fn new() -> Self
    {
        Self {
            fat_type: FatType::Fat32,
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
            reserved_sectors: 0,
            num_fats: 2,
            root_entry_count: 0,
            fat_size: 0,
            root_cluster: 2,
            data_start_sector: 0,
            cached_fat_sector: u32::MAX,
            cached_fat_data: [0; MAX_SECTOR_SIZE],
            total_clusters: 0,
            fsinfo_sector: u32::MAX,
            next_free_hint: u32::MAX,
            free_count_hint: u32::MAX,
        }
    }

    /// First sector of a given cluster.
    ///
    /// Clusters 0 and 1 are reserved by the FAT spec (0 = free-marker,
    /// 1 = reserved); valid data-region clusters start at 2. Callers
    /// MUST filter those sentinels out before reaching this helper.
    /// The clamp here only avoids a panic; every hit is noisy so the
    /// underlying cause (corrupt FAT chain or a block read that
    /// returned zeroed bytes) is visible rather than swallowed.
    pub fn cluster_to_sector(&self, cluster: u32) -> u32
    {
        if cluster < 2
        {
            std::os::seraph::log!(
                warn: "cluster_to_sector({cluster}) — reserved cluster \
                 reached; caller should filter"
            );
        }
        fat_parse::cluster_to_sector(self.data_start_sector, self.sectors_per_cluster, cluster)
    }

    /// Whether `cluster` lies in the data region,
    /// `2 <= cluster < 2 + total_clusters` ([`fat_parse::is_data_cluster`]).
    pub fn is_data_cluster(&self, cluster: u32) -> bool
    {
        fat_parse::is_data_cluster(cluster, self.total_clusters)
    }

    /// The sector of the first FAT copy holding `cluster`'s entry, and the
    /// entry's byte offset in it ([`fat_parse::fat_entry_location`]). `None`
    /// only when the location overflows `u32` or the sector size is zero,
    /// which mount refuses. The caller bounds `cluster` to the data region
    /// ([`Self::is_data_cluster`]): the method does not.
    pub fn fat_entry_location(&self, cluster: u32) -> Option<(u32, usize)>
    {
        fat_parse::fat_entry_location(
            self.fat_type,
            self.reserved_sectors,
            self.bytes_per_sector,
            cluster,
        )
    }

    /// Bytes per sector, as a buffer length: the volume's `BPB_BytsPerSec`,
    /// which mount checked equals the device's logical block size.
    pub fn sector_bytes(&self) -> usize
    {
        usize::from(self.bytes_per_sector)
    }

    /// The sector a [`sector_buffer`] holds: its first [`Self::sector_bytes`]
    /// bytes. Mount refuses a sector size past [`MAX_SECTOR_SIZE`]; were the
    /// state to carry one, the slice is empty, and the block I/O given it
    /// fails as a read or write error.
    pub fn sector<'b>(&self, buf: &'b [u8; MAX_SECTOR_SIZE]) -> &'b [u8]
    {
        buf.get(..self.sector_bytes()).unwrap_or_default()
    }

    /// [`Self::sector`], writable.
    pub fn sector_mut<'b>(&self, buf: &'b mut [u8; MAX_SECTOR_SIZE]) -> &'b mut [u8]
    {
        buf.get_mut(..self.sector_bytes()).unwrap_or_default()
    }

    /// Where byte `offset` of a file lies in its cluster chain
    /// ([`fat_parse::file_position`]). `None` only for a zero sector or
    /// cluster size, which mount refuses.
    pub fn file_position(&self, offset: u64) -> Option<FilePosition>
    {
        fat_parse::file_position(offset, self.sectors_per_cluster, self.bytes_per_sector)
    }

    /// The sectors of `cluster`, in order, from [`Self::cluster_to_sector`].
    /// A sector number past `u32::MAX` saturates there, past every partition
    /// bound, so the block driver refuses it, as for `cluster_to_sector`.
    pub fn cluster_sectors(&self, cluster: u32) -> impl Iterator<Item = u32> + use<>
    {
        let base = self.cluster_to_sector(cluster);
        (0..u32::from(self.sectors_per_cluster)).map(move |s| base.saturating_add(s))
    }

    /// First sector of the FAT16 fixed root directory: past the reserved
    /// sectors and every FAT copy. Mount checked the data region, which
    /// follows the root, starts within `u32`, so this never saturates.
    pub fn root_dir_start(&self) -> u32
    {
        u32::from(self.reserved_sectors)
            .saturating_add(u32::from(self.num_fats).saturating_mul(self.fat_size))
    }

    /// Sectors of the FAT16 fixed root directory: `root_entry_count` 32-byte
    /// entries, rounded up to whole sectors (0 on FAT32).
    pub fn root_dir_sectors(&self) -> u32
    {
        (u32::from(self.root_entry_count) * 32).div_ceil(u32::from(self.bytes_per_sector))
    }

    /// The sectors of the FAT16 fixed root directory, in order (none on
    /// FAT32). They end before the data region, so the sum never saturates.
    pub fn root_sectors(&self) -> impl Iterator<Item = u32> + use<>
    {
        let start = self.root_dir_start();
        (0..self.root_dir_sectors()).map(move |s| start.saturating_add(s))
    }
}

/// Parse the BIOS Parameter Block from sector 0 into `state`.
///
/// Decodes geometry via [`fat_parse::parse_bpb_geometry`], copies it into
/// `state`, and emits the detection and geometry log lines the driver has
/// always produced. Returns `false` after logging the reason on an invalid
/// boot signature, a zero `bytes_per_sector` / `sectors_per_cluster`, a
/// sector size other than the device's logical block size `block_size`, an
/// inconsistent geometry, or a FAT12 cluster count.
pub fn parse_bpb(sector_data: &[u8], block_size: u32, state: &mut FatState) -> bool
{
    let geom = match fat_parse::parse_bpb_geometry(sector_data, block_size)
    {
        Ok(geom) => geom,
        Err(fat_parse::BpbError::BadSignature) =>
        {
            std::os::seraph::log!(warn: "invalid boot signature");
            return false;
        }
        Err(fat_parse::BpbError::ZeroDivisor) =>
        {
            std::os::seraph::log!(
                warn: "invalid BPB: bytes_per_sector or sectors_per_cluster is zero"
            );
            return false;
        }
        Err(fat_parse::BpbError::UnsupportedSectorSize) =>
        {
            std::os::seraph::log!(
                warn: "unsupported BPB: bytes_per_sector is not the device block size {block_size}"
            );
            return false;
        }
        Err(fat_parse::BpbError::BadGeometry) =>
        {
            std::os::seraph::log!(
                warn: "invalid BPB: inconsistent geometry (no FAT copy or reserved sector, \
                 data-region \
                 start overflows, cluster count exceeds the FAT, or FAT32 root outside the data \
                 region)"
            );
            return false;
        }
        Err(fat_parse::BpbError::Fat12) =>
        {
            std::os::seraph::log!(
                warn: "unsupported BPB: fewer than {} clusters (FAT12)",
                fat_parse::FAT16_MIN_CLUSTERS
            );
            return false;
        }
    };

    state.bytes_per_sector = geom.bytes_per_sector;
    state.sectors_per_cluster = geom.sectors_per_cluster;
    state.reserved_sectors = geom.reserved_sectors;
    state.num_fats = geom.num_fats;
    state.root_entry_count = geom.root_entry_count;
    state.fat_size = geom.fat_size;
    state.root_cluster = geom.root_cluster;
    state.data_start_sector = geom.data_start_sector;
    state.total_clusters = geom.total_clusters;
    state.fat_type = geom.fat_type;
    // FSInfo is set only for a FAT32 volume that names a sector inside the
    // reserved region; otherwise the u32::MAX sentinel from FatState::new()
    // stands.
    if let Some(fsinfo) = geom.fsinfo_sector
    {
        state.fsinfo_sector = fsinfo;
    }

    match geom.fat_type
    {
        FatType::Fat16 => std::os::seraph::log!("detected FAT16"),
        FatType::Fat32 => std::os::seraph::log!("detected FAT32"),
    }

    std::os::seraph::log!(
        debug: "sectors_per_cluster={:#018x}",
        u64::from(state.sectors_per_cluster)
    );
    std::os::seraph::log!(debug: "total_clusters={:#018x}", u64::from(geom.total_clusters));
    std::os::seraph::log!(
        debug: "data_start_sector={:#018x}",
        u64::from(state.data_start_sector)
    );

    true
}
