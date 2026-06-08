// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// fs/fat/fat-parse/src/lib.rs

//! Pure FAT on-disk structure decoders.
//!
//! Decodes the BIOS Parameter Block geometry and FAT directory entries
//! (8.3 short names, long-file-name runs, case-insensitive matching) from raw
//! sector bytes. This crate performs no I/O and holds no filesystem state: the
//! `fatfs` service reads sectors over a block-device IPC, hands the bytes here,
//! and keeps the geometry/cache/mutation engine on its side. Keeping the parse
//! of untrusted on-disk structures pure and host-testable is the point — see
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]

// ── BIOS Parameter Block ────────────────────────────────────────────────────

/// Sector size in bytes (fixed at 512 for block device IPC).
pub const SECTOR_SIZE: usize = 512;

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
}

/// Geometry decoded from a FAT BPB (sector 0).
///
/// Mirrors the fields the `fatfs` service copies into its `FatState`. The
/// service owns the cached-FAT-sector and advisory-hint state; this struct
/// carries only what the pure decode produces. `fsinfo_sector` is `Some` only
/// for a FAT32 volume whose `FSInfo` field names a real sector (not the
/// `0`/`0xFFFF` "absent" markers), so the caller assigns it conditionally and
/// otherwise keeps its `u32::MAX` sentinel.
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

/// Decode and validate the BIOS Parameter Block from sector 0.
///
/// Validates the boot signature and the two divisor fields, then computes the
/// data-region start, total cluster count, FAT variant (per the Microsoft
/// FAT32 specification's `< 65525` rule), and — for FAT32 — the `FSInfo` sector.
///
/// # Errors
/// Returns [`BpbError::BadSignature`] when bytes 510/511 are not `0x55 0xAA`,
/// or [`BpbError::ZeroDivisor`] when `bytes_per_sector` or
/// `sectors_per_cluster` is zero.
pub fn parse_bpb_geometry(sector_data: &[u8; SECTOR_SIZE]) -> Result<BpbGeometry, BpbError>
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

    let data_start_sector =
        u32::from(reserved_sectors) + u32::from(num_fats) * fat_size + root_dir_sectors;

    let data_sectors = total_sectors.saturating_sub(data_start_sector);
    let total_clusters = data_sectors / u32::from(sectors_per_cluster);

    // FAT type determination per Microsoft specification.
    let (fat_type, fsinfo_sector) = if total_clusters < 65525
    {
        (FatType::Fat16, None)
    }
    else
    {
        // FAT32 extended BPB: FSInfo sector LBA at offset 48 (2 bytes). A value
        // of 0 or 0xFFFF means "no FSInfo sector"; the caller holds the
        // u32::MAX sentinel in those cases so the allocator skips the load and
        // falls back to a full FAT scan.
        let fsinfo = u16::from_le_bytes([sector_data[48], sector_data[49]]);
        let fsinfo_sector = if fsinfo != 0 && fsinfo != 0xFFFF
        {
            Some(u32::from(fsinfo))
        }
        else
        {
            None
        };
        (FatType::Fat32, fsinfo_sector)
    };

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

/// First sector of `cluster` within the data region.
///
/// Clusters 0 and 1 are reserved by the FAT spec (0 = free-marker,
/// 1 = reserved); valid data-region clusters start at 2. A reserved cluster
/// clamps to `data_start_sector` rather than underflowing `cluster - 2`. The
/// I/O caller is expected to filter reserved clusters and log the hit; this
/// function only avoids the underflow.
#[must_use]
pub fn cluster_to_sector(data_start_sector: u32, sectors_per_cluster: u8, cluster: u32) -> u32
{
    if cluster < 2
    {
        return data_start_sector;
    }
    data_start_sector + (cluster - 2) * u32::from(sectors_per_cluster)
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
            // Provisional length: seq*13 chars, trimmed downward when
            // the first 0x0000 / 0xFFFF terminator is observed below.
            self.len = (seq as usize) * 13;
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
                // Casts are range-safe: ch is 16 bits and BMP-only here
                // (surrogate range handled above).
                #[allow(clippy::cast_possible_truncation)]
                {
                    out[pos] = 0xE0 | (ch >> 12) as u8;
                    out[pos + 1] = 0x80 | ((ch >> 6) & 0x3F) as u8;
                    out[pos + 2] = 0x80 | (ch & 0x3F) as u8;
                }
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
/// Returns `None` for end-of-directory (`0x00`), deleted (`0xE5`),
/// volume-label, and LFN entries (`attr=0x0F`). The returned
/// [`DirEntry`] carries `lfn_len = 0`; callers that have accumulated
/// an LFN run via [`LfnAccum`] populate `lfn` / `lfn_len` themselves.
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
    if raw[11] == 0x0F
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

#[cfg(test)]
mod tests
{
    use super::*;

    /// Build a BPB sector 0 with a valid boot signature and the given fields.
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
    ) -> [u8; SECTOR_SIZE]
    {
        let mut s = [0u8; SECTOR_SIZE];
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

    /// A FAT16 volume: small enough that total_clusters < 65525.
    /// data_start = 1 + 2*20 + 32 = 73; clusters = (8192-73)/4 = 2029.
    fn fat16_sector() -> [u8; SECTOR_SIZE]
    {
        bpb_sector(512, 4, 1, 2, 512, 8192, 20, 0, 0, 0, 0)
    }

    /// A FAT32 volume: large enough that total_clusters >= 65525.
    /// data_start = 32 + 2*1000 = 2032; clusters = (300000-2032)/1 = 297968.
    fn fat32_sector(fsinfo: u16) -> [u8; SECTOR_SIZE]
    {
        bpb_sector(512, 1, 32, 2, 0, 0, 0, 300_000, 1000, 2, fsinfo)
    }

    #[test]
    fn parse_bpb_geometry_rejects_missing_boot_signature()
    {
        let mut s = fat16_sector();
        s[510] = 0x00;
        assert!(matches!(
            parse_bpb_geometry(&s),
            Err(BpbError::BadSignature)
        ));
    }

    #[test]
    fn parse_bpb_geometry_rejects_zero_bytes_per_sector_or_sectors_per_cluster()
    {
        let zero_bps = bpb_sector(0, 4, 1, 2, 512, 8192, 20, 0, 0, 0, 0);
        assert!(matches!(
            parse_bpb_geometry(&zero_bps),
            Err(BpbError::ZeroDivisor)
        ));
        let zero_spc = bpb_sector(512, 0, 1, 2, 512, 8192, 20, 0, 0, 0, 0);
        assert!(matches!(
            parse_bpb_geometry(&zero_spc),
            Err(BpbError::ZeroDivisor)
        ));
    }

    #[test]
    fn parse_bpb_geometry_detects_fat16_below_cluster_threshold()
    {
        let g = parse_bpb_geometry(&fat16_sector())
            .ok()
            .expect("valid FAT16");
        assert!(matches!(g.fat_type, FatType::Fat16));
        assert_eq!(g.total_clusters, 2029);
        assert_eq!(g.data_start_sector, 73);
        assert_eq!(g.fat_size, 20);
        // FAT16 leaves FSInfo absent regardless of the bytes at offset 48.
        assert_eq!(g.fsinfo_sector, None);
    }

    #[test]
    fn parse_bpb_geometry_detects_fat32_at_and_above_threshold()
    {
        let g = parse_bpb_geometry(&fat32_sector(1))
            .ok()
            .expect("valid FAT32");
        assert!(matches!(g.fat_type, FatType::Fat32));
        assert_eq!(g.total_clusters, 297_968);
        // fat_size_16 == 0 falls back to fat_size_32.
        assert_eq!(g.fat_size, 1000);
        assert_eq!(g.root_cluster, 2);
        assert_eq!(g.fsinfo_sector, Some(1));
    }

    #[test]
    fn parse_bpb_geometry_holds_fsinfo_sentinel_for_absent_fsinfo()
    {
        // 0xFFFF and 0 both mean "no FSInfo sector" → None (caller keeps u32::MAX).
        let absent = parse_bpb_geometry(&fat32_sector(0xFFFF))
            .ok()
            .expect("valid FAT32");
        assert_eq!(absent.fsinfo_sector, None);
        let zero = parse_bpb_geometry(&fat32_sector(0))
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
}
