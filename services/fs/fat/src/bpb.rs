// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// fs/fat/src/bpb.rs

//! BIOS Parameter Block parsing and FAT filesystem state.
//!
//! Reads sector 0 of a FAT partition, validates the boot signature, and
//! populates a [`FatState`] with geometry fields needed by the rest of the
//! driver (cluster size, FAT start, data region start, FAT type).

// SECTOR_SIZE and FatType are decoded by the pure, host-testable fat_parse
// crate; the geometry/state machine and block I/O below consume them.
pub use fat_parse::{FatType, SECTOR_SIZE};

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
    /// Cached FAT sector data.
    pub cached_fat_data: [u8; SECTOR_SIZE],
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
            cached_fat_data: [0; SECTOR_SIZE],
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
                "WARNING: cluster_to_sector({cluster}) — reserved cluster \
                 reached; caller should filter"
            );
        }
        fat_parse::cluster_to_sector(self.data_start_sector, self.sectors_per_cluster, cluster)
    }

    /// Bytes per cluster.
    pub fn cluster_size(&self) -> u32
    {
        u32::from(self.sectors_per_cluster) * u32::from(self.bytes_per_sector)
    }
}

/// Parse the BIOS Parameter Block from sector 0 into `state`.
///
/// Decodes geometry via [`fat_parse::parse_bpb_geometry`], copies it into
/// `state`, and emits the detection and geometry log lines the driver has
/// always produced. Returns `false` after logging the reason on an invalid
/// boot signature or a zero `bytes_per_sector` / `sectors_per_cluster`.
pub fn parse_bpb(sector_data: &[u8; SECTOR_SIZE], state: &mut FatState) -> bool
{
    let geom = match fat_parse::parse_bpb_geometry(sector_data)
    {
        Ok(geom) => geom,
        Err(fat_parse::BpbError::BadSignature) =>
        {
            std::os::seraph::log!("invalid boot signature");
            return false;
        }
        Err(fat_parse::BpbError::ZeroDivisor) =>
        {
            std::os::seraph::log!("invalid BPB: bytes_per_sector or sectors_per_cluster is zero");
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
    // FSInfo is set only for a FAT32 volume that names a real sector; otherwise
    // the u32::MAX sentinel from FatState::new() stands.
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
        "sectors_per_cluster={:#018x}",
        u64::from(state.sectors_per_cluster)
    );
    std::os::seraph::log!("total_clusters={:#018x}", u64::from(geom.total_clusters));
    std::os::seraph::log!(
        "data_start_sector={:#018x}",
        u64::from(state.data_start_sector)
    );

    true
}
