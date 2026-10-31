// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/fat-parse/src/lib.rs

//! Pure FAT on-disk structure decoders.
//!
//! Decodes the BIOS Parameter Block geometry and FAT directory entries
//! (8.3 short names, long-file-name runs, case-insensitive matching) from raw
//! sector bytes, locates every slot an entry occupies for its removal
//! ([`RemoveRunScan`]), finds a run of free slots for a new entry
//! ([`FreeRunScan`]), and bounds cluster numbers to the data region
//! ([`is_data_cluster`]). This crate performs no I/O and holds no filesystem
//! state: the `fatfs` service reads sectors over a block-device IPC, hands the
//! bytes here, and keeps the geometry/cache/mutation engine on its side.
//! Keeping the parse of untrusted on-disk structures pure and host-testable is
//! the point — see
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]

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

/// Most cache slots a `fatfs` page cache holds, each one page. The cache
/// takes a slot's page from memmgr on the slot's first use, so a mount pays
/// only for the slots it fills. Defined here, in the host-tested library,
/// so the svctest harness that checks the cache's bounds reads the same
/// value the driver uses.
pub const SLOT_COUNT: usize = 128;

/// Most pages the `fatfs` cache holds beyond [`SLOT_COUNT`]: it requests a
/// replacement page from memmgr only while its quarantined pages (still
/// mapped by a client) and clean spares number fewer than this. Shared with
/// svctest as [`SLOT_COUNT`] is.
pub const QUARANTINE_MAX: usize = 32;

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
    /// reserved sector (the FAT would overlay the boot sector), the data
    /// region's start overflows a 32-bit sector number, the volume has
    /// more clusters than its FAT has entries for (or than FAT32's largest
    /// cluster number allows), so a cluster in the data region would have
    /// no FAT entry, or one past the FAT, or a FAT32 root cluster lies
    /// outside the data region.
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
    pub root_cluster: u32,
    pub data_start_sector: u32,
    pub total_clusters: u32,
    pub fat_type: FatType,
    pub fsinfo_sector: Option<u32>,
}

/// Decode and validate the BIOS Parameter Block from sector 0, read from a
/// device whose logical block size is `device_block_size` bytes.
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
/// the data region's start overflows, the FAT cannot hold an entry for
/// every cluster, or a FAT32 root cluster lies outside the data region.
pub fn parse_bpb_geometry(
    sector_data: &[u8],
    device_block_size: u32,
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
    if bytes_per_sector == 0 || sectors_per_cluster == 0
    {
        return Err(BpbError::ZeroDivisor);
    }
    if !is_sector_size(usize::from(bytes_per_sector))
    {
        return Err(BpbError::UnsupportedSectorSize);
    }
    // The FAT starts after the reserved sectors, the boot sector among
    // them, and every FAT write goes to each of the num_fats copies.
    if num_fats == 0 || reserved_sectors == 0
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
    let root_dir_sectors = (u32::from(root_entry_count) * 32).div_ceil(u32::from(bytes_per_sector));

    let data_start_sector = u32::from(num_fats)
        .checked_mul(fat_size)
        .and_then(|fats| fats.checked_add(u32::from(reserved_sectors)))
        .and_then(|start| start.checked_add(root_dir_sectors))
        .ok_or(BpbError::BadGeometry)?;

    let data_sectors = total_sectors.saturating_sub(data_start_sector);
    let total_clusters = data_sectors / u32::from(sectors_per_cluster);

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
    // The FAT32 root directory is an ordinary cluster chain, so its first
    // cluster must lie in the data region like any other.
    if matches!(fat_type, FatType::Fat32) && !is_data_cluster(root_cluster, total_clusters)
    {
        return Err(BpbError::BadGeometry);
    }

    Ok(BpbGeometry {
        bytes_per_sector,
        sectors_per_cluster,
        reserved_sectors,
        num_fats,
        root_entry_count,
        fat_size,
        root_cluster,
        data_start_sector,
        total_clusters,
        fat_type,
        fsinfo_sector,
    })
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
fn named_fsinfo_sector(sector_data: &[u8], reserved_sectors: u16) -> Option<u32>
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
    let (entry_bytes, max_clusters) = match fat_type
    {
        FatType::Fat16 => (2u64, 0xFFF5u64),
        FatType::Fat32 => (4u64, 0x0FFF_FFF5u64),
    };
    let fat_entries = u64::from(fat_size) * u64::from(bytes_per_sector) / entry_bytes;
    let clusters = u64::from(total_clusters);
    if clusters + 2 > fat_entries || clusters > max_clusters
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
    if cluster < 2
    {
        return data_start_sector;
    }
    data_start_sector.saturating_add((cluster - 2).saturating_mul(u32::from(sectors_per_cluster)))
}

/// Whether `cluster` names a cluster of the data region of a volume with
/// `total_clusters` data clusters: `2 <= cluster < 2 + total_clusters`.
///
/// A cluster number read from the FAT or a directory entry is untrusted
/// on-disk input; one outside this range is a corrupt chain or entry.
#[must_use]
pub fn is_data_cluster(cluster: u32, total_clusters: u32) -> bool
{
    cluster >= 2 && cluster - 2 < total_clusters
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

    /// Write the user-visible name (LFN if present, else NT-case-aware
    /// 8.3) into `out`. Returns the number of bytes written.
    ///
    /// `out` must be at least [`MAX_LFN_UTF8`] bytes; the function
    /// silently truncates otherwise.
    #[must_use]
    pub fn write_display_name(&self, out: &mut [u8]) -> usize
    {
        if self.lfn_len > 0
        {
            let len = usize::from(self.lfn_len).min(out.len());
            out[..len].copy_from_slice(&self.lfn[..len]);
            return len;
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
    pub fn add_lfn_entry(&mut self, raw: &[u8])
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
        // 260, capped to 255 by the protocol).
        if seq == 0 || seq as usize > MAX_LFN_CHARS.div_ceil(13)
        {
            self.reset();
            return;
        }
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
            if !self.saw_last || chksum != self.chksum || seq + 1 != self.last_seq
            {
                self.reset();
                return;
            }
            self.last_seq = seq;
        }

        // Character byte offsets within the 32-byte entry: 5 + 6 + 2.
        let offsets: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        let base = (seq as usize - 1) * 13;
        let mut saw_terminator = false;
        for (i, &off) in offsets.iter().enumerate()
        {
            let pos = base + i;
            if pos >= MAX_LFN_CHARS
            {
                break;
            }
            let ch = u16::from_le_bytes([raw[off], raw[off + 1]]);
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
            self.chars[pos] = ch;
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
        let mut pos = 0;
        let mut i = 0;
        while i < self.len
        {
            let ch = self.chars[i];
            if (0xD800..=0xDBFF).contains(&ch)
            {
                if i + 1 >= self.len
                {
                    return None;
                }
                let low = self.chars[i + 1];
                if !(0xDC00..=0xDFFF).contains(&low)
                {
                    return None;
                }
                let cp = 0x1_0000 + (u32::from(ch - 0xD800) << 10) + u32::from(low - 0xDC00);
                if pos + 4 > out.len()
                {
                    return None;
                }
                // Casts are range-safe: cp is a Unicode scalar value
                // ≤ 0x10_FFFF; each byte mask narrows to ≤ 0xFF.
                #[allow(clippy::cast_possible_truncation)]
                {
                    out[pos] = 0xF0 | (cp >> 18) as u8;
                    out[pos + 1] = 0x80 | ((cp >> 12) & 0x3F) as u8;
                    out[pos + 2] = 0x80 | ((cp >> 6) & 0x3F) as u8;
                    out[pos + 3] = 0x80 | (cp & 0x3F) as u8;
                }
                pos += 4;
                i += 2;
            }
            else if (0xDC00..=0xDFFF).contains(&ch)
            {
                return None;
            }
            else if ch < 0x80
            {
                if pos + 1 > out.len()
                {
                    return None;
                }
                // Cast is range-safe: ch < 0x80 fits in a u8.
                #[allow(clippy::cast_possible_truncation)]
                {
                    out[pos] = ch as u8;
                }
                pos += 1;
                i += 1;
            }
            else if ch < 0x800
            {
                if pos + 2 > out.len()
                {
                    return None;
                }
                // Casts are range-safe: ch < 0x800 fits in 11 bits.
                #[allow(clippy::cast_possible_truncation)]
                {
                    out[pos] = 0xC0 | (ch >> 6) as u8;
                    out[pos + 1] = 0x80 | (ch & 0x3F) as u8;
                }
                pos += 2;
                i += 1;
            }
            else
            {
                if pos + 3 > out.len()
                {
                    return None;
                }
                out[pos] = 0xE0 | (ch >> 12) as u8;
                out[pos + 1] = 0x80 | ((ch >> 6) & 0x3F) as u8;
                out[pos + 2] = 0x80 | (ch & 0x3F) as u8;
                pos += 3;
                i += 1;
            }
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
        let mut buf = [0u8; MAX_LFN_UTF8];
        let Some(len) = self.assemble_utf8(&mut buf)
        else
        {
            return false;
        };
        if len != name.len()
        {
            return false;
        }
        for (a, b) in buf[..len].iter().zip(name.iter())
        {
            if to_upper(*a) != to_upper(*b)
            {
                return false;
            }
        }
        true
    }
}

impl Default for LfnAccum
{
    fn default() -> Self
    {
        Self::new()
    }
}

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
pub fn parse_dir_entry(raw: &[u8]) -> Option<DirEntry>
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
/// the space-padded 8.3 name in the directory entry.
#[must_use]
pub fn name_matches(entry_name: &[u8; 11], component: &[u8]) -> bool
{
    let mut padded = [b' '; 11];
    let dot_pos = component.iter().position(|&b| b == b'.');
    let (base, ext) = if let Some(dp) = dot_pos
    {
        (&component[..dp], &component[dp + 1..])
    }
    else
    {
        (component, &[] as &[u8])
    };
    for (i, &b) in base.iter().take(8).enumerate()
    {
        padded[i] = to_upper(b);
    }
    for (i, &b) in ext.iter().take(3).enumerate()
    {
        padded[8 + i] = to_upper(b);
    }
    *entry_name == padded
}

/// ASCII uppercase fold of one byte; non-ASCII-lowercase bytes pass through unchanged.
#[must_use]
pub fn to_upper(b: u8) -> u8
{
    if b.is_ascii_lowercase() { b - 32 } else { b }
}

fn to_lower(b: u8) -> u8
{
    if b.is_ascii_uppercase() { b + 32 } else { b }
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

    let mut pos = 0;
    let mut base_end = 8;
    while base_end > 0 && raw[base_end - 1] == b' '
    {
        base_end -= 1;
    }
    for &b in &raw[..base_end]
    {
        if pos >= out.len()
        {
            return pos;
        }
        out[pos] = if lower_base { to_lower(b) } else { b };
        pos += 1;
    }

    let mut ext_end = 11;
    while ext_end > 8 && raw[ext_end - 1] == b' '
    {
        ext_end -= 1;
    }
    if ext_end > 8
    {
        if pos >= out.len()
        {
            return pos;
        }
        out[pos] = b'.';
        pos += 1;
        for &b in &raw[8..ext_end]
        {
            if pos >= out.len()
            {
                return pos;
            }
            out[pos] = if lower_ext { to_lower(b) } else { b };
            pos += 1;
        }
    }
    pos
}

// ── Removal slot run ────────────────────────────────────────────────────────

/// Maximum directory slots one entry occupies: a 20-slot LFN run
/// (255 chars / 13 chars per slot) plus the trailing 8.3 entry.
pub const MAX_SLOT_RUN: usize = MAX_LFN_CHARS.div_ceil(13) + 1;

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
    slots: [L; MAX_SLOT_RUN],
    len: usize,
}

impl<L: Copy + Default> RemoveRunScan<L>
{
    /// An empty scan: no LFN run accumulated, no slot positions recorded.
    #[must_use]
    pub fn new() -> Self
    {
        Self {
            lfn: LfnAccum::new(),
            slots: [L::default(); MAX_SLOT_RUN],
            len: 0,
        }
    }

    fn reset(&mut self)
    {
        self.lfn.reset();
        self.len = 0;
    }

    /// Every slot the entry the last [`RemoveStep::Found`] reported
    /// occupies: its LFN slots in on-disk order, then the 8.3 slot.
    /// Meaningful only after [`Self::step`] returns `Found`.
    #[must_use]
    pub fn run(&self) -> &[L]
    {
        &self.slots[..self.len]
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
                self.len = 0;
            }
            self.lfn.add_lfn_entry(raw);
            // The last slot stays free for the 8.3 entry.
            if self.len < MAX_SLOT_RUN - 1
            {
                self.slots[self.len] = loc;
                self.len += 1;
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
                    self.len = 0;
                }
                self.slots[self.len] = loc;
                self.len += 1;
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
pub struct FreeRunScan<L>
{
    slots: [L; MAX_SLOT_RUN],
    len: usize,
    count: usize,
    past_end: bool,
}

impl<L: Copy + Default> FreeRunScan<L>
{
    /// A scan for a run of `count` free slots, clamped to `1..=MAX_SLOT_RUN`.
    #[must_use]
    pub fn new(count: usize) -> Self
    {
        Self {
            slots: [L::default(); MAX_SLOT_RUN],
            len: 0,
            count: count.clamp(1, MAX_SLOT_RUN),
            past_end: false,
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
    /// only after [`Self::step`] returns `true`.
    #[must_use]
    pub fn run(&self) -> &[L]
    {
        &self.slots[..self.len]
    }

    /// Feed the slot at `loc` whose first byte is `first`; once the scan is
    /// [past the end](Self::past_end) the byte is ignored. Returns `true`
    /// when the run holds `count` slots; a step after that changes nothing
    /// and returns `true` again.
    pub fn step(&mut self, first: u8, loc: L) -> bool
    {
        if self.len >= self.count
        {
            return true;
        }
        if first == 0x00
        {
            self.past_end = true;
        }
        if self.past_end || first == 0xE5
        {
            self.slots[self.len] = loc;
            self.len += 1;
        }
        else
        {
            self.len = 0;
        }
        self.len >= self.count
    }
}

// ── Long-name encoding ──────────────────────────────────────────────────────

/// Encode the UTF-8 name `name` as the UTF-16 code units of a FAT long name
/// (UCS-2, with a character outside the Basic Multilingual Plane as a
/// surrogate pair, the form [`LfnAccum::assemble_utf8`] decodes), into
/// `out`. Returns the code-unit count.
///
/// Returns `None` when `name` is not UTF-8 or needs more than
/// [`MAX_LFN_CHARS`] code units.
#[must_use]
pub fn encode_lfn(name: &[u8], out: &mut [u16; MAX_LFN_CHARS]) -> Option<usize>
{
    let text = core::str::from_utf8(name).ok()?;
    let mut len = 0;
    for ch in text.chars()
    {
        let mut units = [0u16; 2];
        for &unit in ch.encode_utf16(&mut units).iter()
        {
            *out.get_mut(len)? = unit;
            len += 1;
        }
    }
    Some(len)
}

// ── Short-name numeric tails ────────────────────────────────────────────────

/// Largest numeric tail the Microsoft FAT specification's short-name scheme
/// generates (`~999999`): six digits after the `~` in an eight-byte base.
pub const MAX_NUMERIC_TAIL: u32 = 999_999;

/// Most entries a FAT directory holds (the specification caps a directory
/// at 65536 32-byte entries). A directory therefore always has a free tail
/// at or below `DIR_ENTRIES_MAX + 1`.
pub const DIR_ENTRIES_MAX: u32 = 65_536;

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
    let mut digits = [0u8; 6];
    let mut n = tail;
    let mut ndigits = 0;
    while n > 0
    {
        // Cast is range-safe: n % 10 < 10.
        #[allow(clippy::cast_possible_truncation)]
        let d = (n % 10) as u8;
        digits[5 - ndigits] = b'0' + d;
        ndigits += 1;
        n /= 10;
    }
    let base_len = basis[..8]
        .iter()
        .rposition(|&b| b != b' ')
        .map_or(0, |p| p + 1);
    let keep = base_len.min(8 - 1 - ndigits);
    let mut out = [b' '; 11];
    out[..keep].copy_from_slice(&basis[..keep]);
    out[keep] = b'~';
    out[keep + 1..keep + 1 + ndigits].copy_from_slice(&digits[6 - ndigits..]);
    out[8..].copy_from_slice(&basis[8..]);
    Some(out)
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
    let base_end = sfn[..8].iter().rposition(|&b| b != b' ')? + 1;
    let tilde = sfn[..base_end].iter().rposition(|&b| b == b'~')?;
    let digits = &sfn[tilde + 1..base_end];
    if digits.is_empty() || digits.len() > 6 || digits[0] == b'0'
    {
        return None;
    }
    let mut tail = 0u32;
    for &d in digits
    {
        if !d.is_ascii_digit()
        {
            return None;
        }
        tail = tail * 10 + u32::from(d - b'0');
    }
    (compose_tailed_name(basis, tail)? == *sfn).then_some(tail)
}

/// The numeric tails one directory's short names use for one basis, for
/// tails up to `DIR_ENTRIES_MAX + 1`: the range the lowest free tail always
/// lies in, since the directory has at most [`DIR_ENTRIES_MAX`] entries.
pub struct TailSet
{
    bits: [u64; TAIL_SET_WORDS],
}

/// Words of [`TailSet`]'s bitmap: one bit per tail `0..=DIR_ENTRIES_MAX + 1`.
const TAIL_SET_WORDS: usize = (DIR_ENTRIES_MAX as usize + 2).div_ceil(64);

impl TailSet
{
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            bits: [0; TAIL_SET_WORDS],
        }
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
        (1..=DIR_ENTRIES_MAX + 1).find(|&t| self.bits[t as usize / 64] & (1 << (t % 64)) == 0)
    }
}

impl Default for TailSet
{
    fn default() -> Self
    {
        Self::new()
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Build a BPB sector 0 with a valid boot signature and the given fields.
    // too_many_arguments: one argument per BPB field the tests vary, so each
    // test states the geometry it exercises in one call.
    #[allow(clippy::too_many_arguments)]
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

    /// A FAT16 volume: 4085 <= total_clusters < 65525.
    /// data_start = 1 + 2*32 + 32 = 97; clusters = (8192-97)/1 = 8095,
    /// within the 32 * 256 = 8192 entries one FAT holds.
    fn fat16_sector() -> [u8; 512]
    {
        bpb_sector(512, 1, 1, 2, 512, 8192, 32, 0, 0, 0, 0)
    }

    /// A FAT32 volume: large enough that total_clusters >= 65525.
    /// data_start = 32 + 2*2400 = 4832; clusters = (300000-4832)/1 = 295168,
    /// within the 2400 * 128 = 307200 entries one FAT holds.
    fn fat32_sector(fsinfo: u16) -> [u8; 512]
    {
        bpb_sector(512, 1, 32, 2, 0, 0, 0, 300_000, 2400, 2, fsinfo)
    }

    #[test]
    fn parse_bpb_geometry_rejects_missing_boot_signature()
    {
        let mut s = fat16_sector();
        s[510] = 0x00;
        assert!(matches!(
            parse_bpb_geometry(&s, 512),
            Err(BpbError::BadSignature)
        ));
    }

    #[test]
    fn parse_bpb_geometry_rejects_zero_bytes_per_sector_or_sectors_per_cluster()
    {
        let zero_bps = bpb_sector(0, 4, 1, 2, 512, 8192, 20, 0, 0, 0, 0);
        assert!(matches!(
            parse_bpb_geometry(&zero_bps, 512),
            Err(BpbError::ZeroDivisor)
        ));
        let zero_spc = bpb_sector(512, 0, 1, 2, 512, 8192, 20, 0, 0, 0, 0);
        assert!(matches!(
            parse_bpb_geometry(&zero_spc, 512),
            Err(BpbError::ZeroDivisor)
        ));
    }

    #[test]
    fn parse_bpb_geometry_detects_fat16_below_cluster_threshold()
    {
        let g = parse_bpb_geometry(&fat16_sector(), 512)
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
            parse_bpb_geometry(&fat12, 512),
            Err(BpbError::Fat12)
        ));
        let g = parse_bpb_geometry(
            &bpb_sector(512, 1, 1, 2, 512, 73 + 4085, 20, 0, 0, 0, 0),
            512,
        )
        .ok()
        .expect("the fewest clusters FAT16 has");
        assert!(matches!(g.fat_type, FatType::Fat16));
    }

    #[test]
    fn parse_bpb_geometry_detects_fat32_at_and_above_threshold()
    {
        let g = parse_bpb_geometry(&fat32_sector(1), 512)
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
        let absent = parse_bpb_geometry(&fat32_sector(0xFFFF), 512)
            .ok()
            .expect("valid FAT32");
        assert_eq!(absent.fsinfo_sector, None);
        let zero = parse_bpb_geometry(&fat32_sector(0), 512)
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
    fn parse_bpb_geometry_rejects_sectors_other_than_the_device_block()
    {
        // A 4 KiB-sector volume on a 512-byte device, and the reverse: the
        // cache and FAT walker index one device block per sector.
        let large = bpb_sector(4096, 1, 1, 2, 512, 8192, 20, 0, 0, 0, 0);
        assert!(matches!(
            parse_bpb_geometry(&large, 512),
            Err(BpbError::UnsupportedSectorSize)
        ));
        assert!(matches!(
            parse_bpb_geometry(&fat16_sector(), 4096),
            Err(BpbError::UnsupportedSectorSize)
        ));
        // 1536 matches its device but is no FAT sector size.
        let odd = bpb_sector(1536, 1, 1, 2, 512, 8192, 20, 0, 0, 0, 0);
        assert!(matches!(
            parse_bpb_geometry(&odd, 1536),
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
        let g = parse_bpb_geometry(&s, 4096).ok().expect("4Kn FAT32");
        assert_eq!(g.bytes_per_sector, 4096);
        assert!(matches!(g.fat_type, FatType::Fat32));
        assert_eq!(g.total_clusters, 300_000 - 632);
        // The same table read as 512-byte sectors holds an eighth of the
        // entries, too few for the clusters.
        let small = bpb_sector(512, 1, 32, 2, 0, 0, 0, 300_000, 300, 2, 1);
        assert!(matches!(
            parse_bpb_geometry(&small, 512),
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
    fn lowest_free_tail_passes_the_old_six_tail_limit()
    {
        // Tails 1 through 6 taken, and 8: the seventh colliding name gets ~7
        // where a six-tail scheme failed with NoSpace.
        let b = basis(b"REPORT", b"TXT");
        let mut used = TailSet::new();
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
        let mut used = TailSet::new();
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
        let g = parse_bpb_geometry(&full, 512)
            .ok()
            .expect("FAT holds every cluster");
        assert_eq!(g.total_clusters, 76_798);
        let over = bpb_sector(512, 1, 32, 2, 0, 0, 0, 1232 + 76_799, 600, 2, 0);
        assert!(matches!(
            parse_bpb_geometry(&over, 512),
            Err(BpbError::BadGeometry)
        ));
    }

    #[test]
    fn parse_bpb_geometry_accepts_exactly_the_clusters_a_fat16_table_holds()
    {
        // A 20-sector FAT16 table holds 5120 entries: clusters 2..5120.
        // data_start = 1 + 2*20 + 32 (512 root entries) = 73.
        let full = bpb_sector(512, 1, 1, 2, 512, 73 + 5118, 20, 0, 0, 0, 0);
        let g = parse_bpb_geometry(&full, 512)
            .ok()
            .expect("FAT holds every cluster");
        assert!(matches!(g.fat_type, FatType::Fat16));
        assert_eq!(g.total_clusters, 5118);
        let over = bpb_sector(512, 1, 1, 2, 512, 73 + 5119, 20, 0, 0, 0, 0);
        assert!(matches!(
            parse_bpb_geometry(&over, 512),
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
        assert!(parse_bpb_geometry(&last, 512).is_ok());
        let marker = bpb_sector(512, 1, 32, 2, 0, 0, 0, start + 0x0FFF_FFF6, fat, 2, 0);
        assert!(matches!(
            parse_bpb_geometry(&marker, 512),
            Err(BpbError::BadGeometry)
        ));
    }

    #[test]
    fn parse_bpb_geometry_rejects_a_fat32_root_outside_the_data_region()
    {
        let root_one = bpb_sector(512, 1, 32, 2, 0, 0, 0, 300_000, 2400, 1, 1);
        assert!(matches!(
            parse_bpb_geometry(&root_one, 512),
            Err(BpbError::BadGeometry)
        ));
    }

    #[test]
    fn parse_bpb_geometry_treats_an_fsinfo_sector_past_the_reserved_region_as_absent()
    {
        // 32 reserved sectors: sector 32 is the first FAT sector.
        let g = parse_bpb_geometry(&fat32_sector(32), 512)
            .ok()
            .expect("valid FAT32");
        assert_eq!(g.fsinfo_sector, None);
    }

    #[test]
    fn parse_bpb_geometry_rejects_zero_fats_or_reserved_sectors()
    {
        let no_fats = bpb_sector(512, 4, 1, 0, 512, 8192, 20, 0, 0, 0, 0);
        assert!(matches!(
            parse_bpb_geometry(&no_fats, 512),
            Err(BpbError::BadGeometry)
        ));
        let no_reserved = bpb_sector(512, 4, 0, 2, 512, 8192, 20, 0, 0, 0, 0);
        assert!(matches!(
            parse_bpb_geometry(&no_reserved, 512),
            Err(BpbError::BadGeometry)
        ));
    }

    #[test]
    fn parse_bpb_geometry_rejects_an_overflowing_data_start()
    {
        let huge_fat = bpb_sector(512, 1, 32, 2, 0, 0, 0, u32::MAX, u32::MAX, 2, 0);
        assert!(matches!(
            parse_bpb_geometry(&huge_fat, 512),
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
    fn name_matches_truncates_base_and_ext_to_8_and_3()
    {
        // Only the first 8 base and first 3 ext chars participate (FAT 8.3).
        assert!(name_matches(b"LONGNAMEEXT", b"longnamethatislong.extra"));
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
        assert!(scan.step(b'Q', 4));
        assert_eq!(scan.run(), &[2, 3, 4]);
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
}
