// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// fs/fat/src/bpb.rs

//! BIOS Parameter Block parsing and FAT filesystem state.
//!
//! Reads sector 0 of a FAT partition, validates the boot signature, and
//! populates a [`FatState`] with geometry fields needed by the rest of the
//! driver (cluster size, FAT start, data region start, FAT type).

/// Sector size in bytes (fixed at 512 for block device IPC).
pub const SECTOR_SIZE: usize = 512;

/// FAT variant detected from cluster count.
#[derive(Clone, Copy)]
pub enum FatType
{
    Fat16,
    Fat32,
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
            return self.data_start_sector;
        }
        self.data_start_sector + (cluster - 2) * u32::from(self.sectors_per_cluster)
    }

    /// Bytes per cluster.
    pub fn cluster_size(&self) -> u32
    {
        u32::from(self.sectors_per_cluster) * u32::from(self.bytes_per_sector)
    }
}

/// Parse the BIOS Parameter Block from sector 0.
// clippy::too_many_lines: parse_bpb is a linear decoder for a fixed binary
// layout (FAT16/FAT32 BPB — Microsoft FAT32 File System Specification §3.1).
// Each field extraction has no independent meaning; there is no natural
// split into phases. The validation checks at the end depend on every
// field being in scope. Factoring into per-field helpers would replicate
// boilerplate without improving comprehension.
#[allow(clippy::too_many_lines)]
pub fn parse_bpb(sector_data: &[u8; SECTOR_SIZE], state: &mut FatState) -> bool
{
    // Validate boot signature.
    if sector_data[510] != 0x55 || sector_data[511] != 0xAA
    {
        std::os::seraph::log!("invalid boot signature");
        return false;
    }

    state.bytes_per_sector = u16::from_le_bytes([sector_data[11], sector_data[12]]);
    state.sectors_per_cluster = sector_data[13];
    state.reserved_sectors = u16::from_le_bytes([sector_data[14], sector_data[15]]);
    state.num_fats = sector_data[16];
    state.root_entry_count = u16::from_le_bytes([sector_data[17], sector_data[18]]);

    // Validate fields used as divisors to prevent division by zero.
    if state.bytes_per_sector == 0 || state.sectors_per_cluster == 0
    {
        std::os::seraph::log!("invalid BPB: bytes_per_sector or sectors_per_cluster is zero");
        return false;
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
    state.root_cluster = u32::from_le_bytes([
        sector_data[44],
        sector_data[45],
        sector_data[46],
        sector_data[47],
    ]);

    state.fat_size = if fat_size_16 != 0
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
    let root_dir_sectors =
        (u32::from(state.root_entry_count) * 32).div_ceil(u32::from(state.bytes_per_sector));

    state.data_start_sector = u32::from(state.reserved_sectors)
        + u32::from(state.num_fats) * state.fat_size
        + root_dir_sectors;

    let data_sectors = total_sectors.saturating_sub(state.data_start_sector);
    let total_clusters = data_sectors / u32::from(state.sectors_per_cluster);
    state.total_clusters = total_clusters;

    // FAT type determination per Microsoft specification.
    if total_clusters < 65525
    {
        state.fat_type = FatType::Fat16;
        std::os::seraph::log!("detected FAT16");
    }
    else
    {
        state.fat_type = FatType::Fat32;
        std::os::seraph::log!("detected FAT32");
        // FAT32 extended BPB: `FSInfo` sector LBA at offset 48 (2 bytes).
        // A value of 0 or 0xFFFF means "no `FSInfo` sector"; we hold the
        // u32::MAX sentinel in those cases so the allocator skips load
        // and falls back to a full FAT scan.
        let fsinfo = u16::from_le_bytes([sector_data[48], sector_data[49]]);
        if fsinfo != 0 && fsinfo != 0xFFFF
        {
            state.fsinfo_sector = u32::from(fsinfo);
        }
    }

    std::os::seraph::log!(
        "sectors_per_cluster={:#018x}",
        u64::from(state.sectors_per_cluster)
    );
    std::os::seraph::log!("total_clusters={:#018x}", u64::from(total_clusters));
    std::os::seraph::log!(
        "data_start_sector={:#018x}",
        u64::from(state.data_start_sector)
    );

    true
}
