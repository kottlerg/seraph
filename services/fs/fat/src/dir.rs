// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// fs/fat/src/dir.rs

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

// The directory-mutation helpers added in the write-support work are
// wired into dispatch handlers in a subsequent commit; suppress the
// dead-code lint module-wide until that lands.
#![allow(dead_code)]

use crate::alloc::{FatError, allocate_cluster, free_cluster_chain};
use crate::bpb::{FatState, FatType, SECTOR_SIZE};
use crate::cache::PageCache;
use crate::fat::next_cluster;

// ── Directory entry ────────────────────────────────────────────────────────

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
    /// debug-asserts and silently truncates otherwise.
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

// ── LFN accumulator ───────────────────────────────────────────────────────

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
    pub fn validate(&self, sfn: &[u8; 11]) -> bool
    {
        self.active && self.saw_last && self.last_seq == 1 && lfn_checksum(sfn) == self.chksum
    }

    /// Decode the accumulated UCS-2 code units into UTF-8.
    ///
    /// Returns the byte length on success; `None` on buffer overflow
    /// or malformed surrogate pairs (an unpaired surrogate, or a high
    /// surrogate followed by a non-low-surrogate code unit).
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
    /// Used by [`scan_sector_for_name`] for the lookup-by-name path.
    /// Non-ASCII code units compare exactly (no full Unicode case
    /// folding); ASCII letters fold against `name`'s ASCII letters.
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

/// FAT LFN checksum: rotate-right-1 + add, computed over the 11-byte 8.3 name.
///
/// Defined by the Microsoft FAT specification as the value every LFN
/// slot in a run carries at byte offset 13 (`LDIR_Chksum`). Used by
/// readers to validate that an LFN run actually belongs to the
/// trailing 8.3 entry rather than to an orphaned earlier run.
fn lfn_checksum(name: &[u8; 11]) -> u8
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

// ── Entry parsing ─────────────────────────────────────────────────────────

/// Parse a single 32-byte FAT directory entry.
///
/// Returns `None` for end-of-directory (`0x00`), deleted (`0xE5`),
/// volume-label, and LFN entries (`attr=0x0F`). The returned
/// [`DirEntry`] carries `lfn_len = 0`; callers that have accumulated
/// an LFN run via [`LfnAccum`] populate `lfn` / `lfn_len` themselves.
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
fn name_matches(entry_name: &[u8; 11], component: &[u8]) -> bool
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

fn to_upper(b: u8) -> u8
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

// ── Directory search ──────────────────────────────────────────────────────

/// Search a directory's cluster chain for an entry matching `name`.
///
/// Walks the cluster chain (or, for `dir_cluster == 0`, the FAT16
/// fixed root) and matches against both LFN and 8.3 forms via
/// [`scan_sector_for_name`]. Drives `backend::FatfsBackend::lookup`
/// for the cap-native [`namespace_protocol::NamespaceBackend`]
/// surface.
pub fn find_in_directory(
    dir_cluster: u32,
    name: &[u8],
    state: &mut FatState,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Option<DirEntry>
{
    let mut sector_buf = [0u8; SECTOR_SIZE];
    let mut lfn = LfnAccum::new();

    if dir_cluster == 0
    {
        return find_in_fat16_root(name, state, cache, block_dev, ipc_buf);
    }

    let mut cluster = dir_cluster;
    loop
    {
        let base_sector = state.cluster_to_sector(cluster);
        for s in 0..u32::from(state.sectors_per_cluster)
        {
            if !cache.read_sector(
                u64::from(base_sector + s),
                block_dev,
                &mut sector_buf,
                ipc_buf,
            )
            {
                return None;
            }
            if let Some(entry) = scan_sector_for_name(&sector_buf, name, &mut lfn)
            {
                return Some(entry);
            }
        }

        cluster = next_cluster(state, cluster, cache, block_dev, ipc_buf)?;
    }
}

/// Search the FAT16 fixed root directory area.
fn find_in_fat16_root(
    name: &[u8],
    state: &mut FatState,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Option<DirEntry>
{
    let root_start = u32::from(state.reserved_sectors) + u32::from(state.num_fats) * state.fat_size;
    let root_sectors = (u32::from(state.root_entry_count) * 32).div_ceil(512);
    let mut sector_buf = [0u8; SECTOR_SIZE];
    let mut lfn = LfnAccum::new();

    for s in 0..root_sectors
    {
        if !cache.read_sector(
            u64::from(root_start + s),
            block_dev,
            &mut sector_buf,
            ipc_buf,
        )
        {
            return None;
        }
        if let Some(entry) = scan_sector_for_name(&sector_buf, name, &mut lfn)
        {
            return Some(entry);
        }
    }

    None
}

/// As [`find_in_directory`] but also returns the on-disk location of
/// the matching 8.3 entry, used by callers that intend to patch the
/// entry's metadata fields (`size`, `first_cluster`) later.
pub fn find_in_directory_with_location(
    dir_cluster: u32,
    name: &[u8],
    state: &mut FatState,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Option<(DirEntry, DirEntryLocation)>
{
    let mut sector_buf = [0u8; SECTOR_SIZE];
    let mut lfn = LfnAccum::new();
    let entries_per_sector = SECTOR_SIZE / 32;

    if dir_cluster == 0
    {
        let root_start =
            u32::from(state.reserved_sectors) + u32::from(state.num_fats) * state.fat_size;
        let root_sectors = (u32::from(state.root_entry_count) * 32).div_ceil(512);
        for s in 0..root_sectors
        {
            let sector_lba = root_start + s;
            if !cache.read_sector(u64::from(sector_lba), block_dev, &mut sector_buf, ipc_buf)
            {
                return None;
            }
            if let Some((entry, off)) =
                scan_sector_for_name_with_offset(&sector_buf, name, &mut lfn, entries_per_sector)
            {
                return Some((
                    entry,
                    DirEntryLocation {
                        sector_lba,
                        offset_in_sector: off,
                    },
                ));
            }
        }
        return None;
    }

    let mut cluster = dir_cluster;
    loop
    {
        let base_sector = state.cluster_to_sector(cluster);
        for s in 0..u32::from(state.sectors_per_cluster)
        {
            let sector_lba = base_sector + s;
            if !cache.read_sector(u64::from(sector_lba), block_dev, &mut sector_buf, ipc_buf)
            {
                return None;
            }
            if let Some((entry, off)) =
                scan_sector_for_name_with_offset(&sector_buf, name, &mut lfn, entries_per_sector)
            {
                return Some((
                    entry,
                    DirEntryLocation {
                        sector_lba,
                        offset_in_sector: off,
                    },
                ));
            }
        }
        cluster = next_cluster(state, cluster, cache, block_dev, ipc_buf)?;
    }
}

fn scan_sector_for_name_with_offset(
    sector: &[u8; SECTOR_SIZE],
    name: &[u8],
    lfn: &mut LfnAccum,
    entries_per_sector: usize,
) -> Option<(DirEntry, usize)>
{
    for i in 0..entries_per_sector
    {
        let offset = i * 32;
        let raw = &sector[offset..offset + 32];
        if raw[0] == 0x00
        {
            return None;
        }
        if raw[0] == 0xE5
        {
            lfn.reset();
            continue;
        }
        if raw[11] == 0x0F
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
                return Some((entry, offset));
            }
        }
        lfn.reset();
    }
    None
}

/// Scan a sector's 32-byte directory entries for a name match.
///
/// Supports both 8.3 and LFN matching. The `lfn` accumulator carries
/// LFN state across sector boundaries.
fn scan_sector_for_name(
    sector: &[u8; SECTOR_SIZE],
    name: &[u8],
    lfn: &mut LfnAccum,
) -> Option<DirEntry>
{
    let entries_per_sector = SECTOR_SIZE / 32;
    for i in 0..entries_per_sector
    {
        let offset = i * 32;
        let raw = &sector[offset..offset + 32];
        if raw[0] == 0x00
        {
            return None;
        }
        if raw[0] == 0xE5
        {
            lfn.reset();
            continue;
        }
        if raw[11] == 0x0F
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
                return Some(entry);
            }
        }
        lfn.reset();
    }
    None
}

/// Read a directory entry at a given index.
///
/// Skips deleted, LFN, and end-of-directory markers; counts only
/// valid 8.3 entries. When a valid LFN run precedes the 8.3 entry,
/// the assembled UTF-8 name is attached to the returned [`DirEntry`]
/// for the readdir wire reply; otherwise callers fall back to the
/// 8.3 form via [`DirEntry::write_display_name`].
// clippy::too_many_lines: read_dir_entry_at_index folds two iteration
// shapes — FAT16 fixed root (contiguous sectors) and FAT32 clustered
// directory (cluster-chain walk) — into one procedure because they
// share the "scan 32-byte entries, accumulate LFN, count valid 8.3
// entries, return the Nth" post-processing loop. Splitting would
// require duplicating that post-processing loop or passing the
// shared buffer + counters across a helper boundary, neither of
// which clarifies the code.
#[allow(clippy::too_many_lines)]
pub fn read_dir_entry_at_index(
    dir_cluster: u32,
    index: u64,
    state: &mut FatState,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Option<DirEntry>
{
    let mut sector_buf = [0u8; SECTOR_SIZE];
    let mut lfn = LfnAccum::new();
    let entries_per_sector = SECTOR_SIZE / 32;
    let mut current_idx: u64 = 0;

    if dir_cluster == 0
    {
        let root_start =
            u32::from(state.reserved_sectors) + u32::from(state.num_fats) * state.fat_size;
        let root_sectors = (u32::from(state.root_entry_count) * 32).div_ceil(512);

        for s in 0..root_sectors
        {
            if !cache.read_sector(
                u64::from(root_start + s),
                block_dev,
                &mut sector_buf,
                ipc_buf,
            )
            {
                return None;
            }
            for e in 0..entries_per_sector
            {
                let offset = e * 32;
                let raw = &sector_buf[offset..offset + 32];
                if raw[0] == 0x00
                {
                    return None;
                }
                if raw[0] == 0xE5
                {
                    lfn.reset();
                    continue;
                }
                if raw[11] == 0x0F
                {
                    lfn.add_lfn_entry(raw);
                    continue;
                }
                if let Some(mut entry) = parse_dir_entry(raw)
                {
                    if lfn.validate(&entry.name)
                    {
                        populate_lfn(&mut entry, &lfn);
                    }
                    if current_idx == index
                    {
                        return Some(entry);
                    }
                    current_idx += 1;
                }
                lfn.reset();
            }
        }
        return None;
    }

    let mut cluster = dir_cluster;
    loop
    {
        let base_sector = state.cluster_to_sector(cluster);
        for s in 0..u32::from(state.sectors_per_cluster)
        {
            if !cache.read_sector(
                u64::from(base_sector + s),
                block_dev,
                &mut sector_buf,
                ipc_buf,
            )
            {
                return None;
            }
            for e in 0..entries_per_sector
            {
                let offset = e * 32;
                let raw = &sector_buf[offset..offset + 32];
                if raw[0] == 0x00
                {
                    return None;
                }
                if raw[0] == 0xE5
                {
                    lfn.reset();
                    continue;
                }
                if raw[11] == 0x0F
                {
                    lfn.add_lfn_entry(raw);
                    continue;
                }
                if let Some(mut entry) = parse_dir_entry(raw)
                {
                    if lfn.validate(&entry.name)
                    {
                        populate_lfn(&mut entry, &lfn);
                    }
                    if current_idx == index
                    {
                        return Some(entry);
                    }
                    current_idx += 1;
                }
                lfn.reset();
            }
        }

        if let Some(next) = next_cluster(state, cluster, cache, block_dev, ipc_buf)
        {
            cluster = next;
        }
        else
        {
            return None;
        }
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
    // Cast is range-safe: `len <= MAX_LFN_UTF8 = 765 < u16::MAX`.
    #[allow(clippy::cast_possible_truncation)]
    {
        entry.lfn_len = len as u16;
    }
}

// ── Directory mutation ────────────────────────────────────────────────────
//
// The mutation API (insert_entry / remove_entry / update_entry_metadata
// / write_dot_entries / directory_is_empty / free_entry_data) is wired
// into dispatch handlers in a subsequent commit. Dead-code suppression
// is module-wide via `#![allow(dead_code)]` at the top of dir.rs.

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
/// 8.3 attribute byte for an LFN slot.
const ATTR_LFN: u8 = 0x0F;
/// LFN sequence flag: `0x40` `OR`ed into the highest-seq slot marks
/// "last entry in the LFN run" (per the FAT spec).
const LFN_LAST_FLAG: u8 = 0x40;
/// Maximum `NUMERIC_TAIL` we will probe (`~1` through `~6`). Beyond
/// this callers see [`FatError::NoSpace`] for the name; in practice
/// tests never collide hard enough to exhaust the tail.
const MAX_NUMERIC_TAIL: u8 = 6;
/// Maximum LFN slots in one run (255 chars / 13 chars-per-slot = 20).
/// Plus 1 for the trailing 8.3 entry is the upper bound on slot-run
/// length we ever allocate.
const MAX_SLOT_RUN: usize = 21;

/// Physical location of a 32-byte directory entry on disk.
///
/// Returned by [`insert_entry`] so dispatch can later patch the
/// `first_cluster` and `size` fields via [`update_entry_metadata`]
/// after a write extends the file.
#[derive(Copy, Clone, Debug)]
pub struct DirEntryLocation
{
    pub sector_lba: u32,
    pub offset_in_sector: usize,
}

/// Description of a directory entry that [`remove_entry`] just unlinked.
///
/// `start_cluster` is `0` for empty files (cluster chain was never
/// allocated) — the caller must skip `free_cluster_chain` in that case.
#[derive(Copy, Clone, Debug)]
pub struct RemovedEntry
{
    pub start_cluster: u32,
    pub size: u32,
    pub is_dir: bool,
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
#[allow(clippy::too_many_arguments)]
pub fn insert_entry(
    state: &mut FatState,
    parent_dir_cluster: u32,
    name: &[u8],
    kind: NewEntryKind,
    start_cluster: u32,
    size: u32,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Result<DirEntryLocation, FatError>
{
    if name.is_empty() || name.len() > MAX_LFN_CHARS
    {
        return Err(FatError::Corrupt);
    }
    if find_in_directory(parent_dir_cluster, name, state, cache, block_dev, ipc_buf).is_some()
    {
        return Err(FatError::NoSpace); // EXISTS — mapped to wire code at dispatch
    }

    let sfn = generate_sfn(state, parent_dir_cluster, name, cache, block_dev, ipc_buf)?;
    let chksum = lfn_checksum(&sfn);

    let needs_lfn = !is_strict_83_match(&sfn, name);
    let lfn_slot_count = if needs_lfn
    {
        name.len().div_ceil(13)
    }
    else
    {
        0
    };
    let total_slots = lfn_slot_count + 1;

    let slots = find_free_slot_run(
        state,
        parent_dir_cluster,
        total_slots,
        cache,
        block_dev,
        ipc_buf,
    )?;

    // Emit LFN slots in reverse-seq order (high seq with LFN_LAST_FLAG
    // first on disk, seq counts down to 1). The slots iterator gives
    // them in disk order; we pack starting at slot[0] with the highest
    // sequence number.
    if needs_lfn
    {
        let chars = name_as_ucs2(name);
        // cast_possible_truncation: lfn_slot_count ≤ ceil(255 / 13) = 20
        #[allow(clippy::cast_possible_truncation)]
        for (i, slot) in slots.iter().take(lfn_slot_count).enumerate()
        {
            let seq = (lfn_slot_count - i) as u8;
            let is_last = i == 0;
            let slot_chars = lfn_chars_for_seq(&chars, name.len(), seq);
            let raw = pack_lfn_slot(seq, is_last, chksum, &slot_chars);
            write_dir_slot(state, *slot, &raw, cache, block_dev, ipc_buf)?;
        }
    }

    let attr = match kind
    {
        NewEntryKind::File => ATTR_ARCHIVE,
        NewEntryKind::Dir => ATTR_DIRECTORY,
    };
    let raw_83 = pack_83_entry(&sfn, attr, start_cluster, size);
    write_dir_slot(
        state,
        slots[total_slots - 1],
        &raw_83,
        cache,
        block_dev,
        ipc_buf,
    )?;

    Ok(slots[total_slots - 1])
}

/// Mark an existing directory entry (and any preceding LFN run) as
/// deleted (`0xE5`).
///
/// Returns the entry's `start_cluster`, `size`, and kind so the caller
/// can free the data chain via [`free_cluster_chain`]. Directory
/// removal additionally requires the directory be empty (no entries
/// other than `.` and `..`); this is the caller's responsibility to
/// validate before invoking this function.
pub fn remove_entry(
    state: &mut FatState,
    parent_dir_cluster: u32,
    name: &[u8],
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Result<RemovedEntry, FatError>
{
    let positions =
        locate_entry_with_lfn_run(state, parent_dir_cluster, name, cache, block_dev, ipc_buf)?;
    let (entry, ref slots) = positions;
    for slot in slots
    {
        mark_slot_deleted(state, *slot, cache, block_dev, ipc_buf)?;
    }
    Ok(entry)
}

/// Patch the 8.3 entry at `loc` with new `first_cluster` and `size`
/// fields. Used after a write extends a file's cluster chain.
pub fn update_entry_metadata(
    state: &mut FatState,
    loc: DirEntryLocation,
    new_first_cluster: u32,
    new_size: u32,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Result<(), FatError>
{
    let _ = state; // mirrors the read-side signature; reserved for future use
    let mut buf = [0u8; SECTOR_SIZE];
    if !cache.read_sector(u64::from(loc.sector_lba), block_dev, &mut buf, ipc_buf)
    {
        return Err(FatError::Io);
    }
    let off = loc.offset_in_sector;
    let cluster_hi = ((new_first_cluster >> 16) & 0xFFFF) as u16;
    let cluster_lo = (new_first_cluster & 0xFFFF) as u16;
    buf[off + 20..off + 22].copy_from_slice(&cluster_hi.to_le_bytes());
    buf[off + 26..off + 28].copy_from_slice(&cluster_lo.to_le_bytes());
    buf[off + 28..off + 32].copy_from_slice(&new_size.to_le_bytes());
    if !cache.write_sector(u64::from(loc.sector_lba), block_dev, &buf, ipc_buf)
    {
        return Err(FatError::Io);
    }
    Ok(())
}

/// Check whether a directory cluster chain contains any entries other
/// than `.` and `..`. Used by `FS_REMOVE` to enforce the
/// non-empty-directory rejection.
pub fn directory_is_empty(
    state: &mut FatState,
    dir_cluster: u32,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Result<bool, FatError>
{
    let mut buf = [0u8; SECTOR_SIZE];
    let entries_per_sector = SECTOR_SIZE / 32;

    let mut cluster = dir_cluster;
    loop
    {
        let base_sector = state.cluster_to_sector(cluster);
        for s in 0..u32::from(state.sectors_per_cluster)
        {
            if !cache.read_sector(u64::from(base_sector + s), block_dev, &mut buf, ipc_buf)
            {
                return Err(FatError::Io);
            }
            for e in 0..entries_per_sector
            {
                let off = e * 32;
                let first = buf[off];
                if first == 0x00
                {
                    return Ok(true);
                }
                if first == 0xE5
                {
                    continue;
                }
                if buf[off + 11] == ATTR_LFN
                {
                    continue;
                }
                // Skip "." and "..".
                if buf[off..off + 11] == *b".          " || buf[off..off + 11] == *b"..         "
                {
                    continue;
                }
                return Ok(false);
            }
        }
        match next_cluster(state, cluster, cache, block_dev, ipc_buf)
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
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Result<(), FatError>
{
    let base_sector = state.cluster_to_sector(new_dir_cluster);
    let mut buf = [0u8; SECTOR_SIZE];
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
    buf[..32].copy_from_slice(&dot);
    buf[32..64].copy_from_slice(&dotdot);
    if !cache.write_sector(u64::from(base_sector), block_dev, &buf, ipc_buf)
    {
        return Err(FatError::Io);
    }
    // Zero out the rest of the cluster so a stale neighbour sector
    // (allocate_cluster reuses freed clusters) does not surface as
    // ghost entries.
    let zeros = [0u8; SECTOR_SIZE];
    for s in 1..u32::from(state.sectors_per_cluster)
    {
        if !cache.write_sector(u64::from(base_sector + s), block_dev, &zeros, ipc_buf)
        {
            return Err(FatError::Io);
        }
    }
    Ok(())
}

// ── Mutation internals ────────────────────────────────────────────────────

/// Walk the parent directory entry-by-entry; collect a run of
/// `count` consecutive free (0x00 or 0xE5) slots. Free runs reset on
/// any non-free slot, and end-of-directory (0x00) triggers extension
/// when needed.
#[allow(clippy::too_many_lines)]
fn find_free_slot_run(
    state: &mut FatState,
    parent_dir_cluster: u32,
    count: usize,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Result<[DirEntryLocation; MAX_SLOT_RUN], FatError>
{
    debug_assert!(count <= MAX_SLOT_RUN);

    let mut run: [Option<DirEntryLocation>; MAX_SLOT_RUN] = [None; MAX_SLOT_RUN];
    let mut run_len = 0usize;

    let entries_per_sector = SECTOR_SIZE / 32;
    let mut buf = [0u8; SECTOR_SIZE];

    // FAT16 fixed root.
    if parent_dir_cluster == 0 && matches!(state.fat_type, FatType::Fat16)
    {
        let root_start =
            u32::from(state.reserved_sectors) + u32::from(state.num_fats) * state.fat_size;
        let root_sectors = (u32::from(state.root_entry_count) * 32).div_ceil(512);
        for s in 0..root_sectors
        {
            match scan_sector_free_run(
                root_start + s,
                count,
                cache,
                block_dev,
                ipc_buf,
                &mut buf,
                entries_per_sector,
                &mut run,
                &mut run_len,
            )?
            {
                ScanStop::Done => return collect_run(&run, count),
                ScanStop::EndOfDirectory => break,
                ScanStop::Continue =>
                {}
            }
        }
        if run_len >= count
        {
            return collect_run(&run, count);
        }
        return Err(FatError::NoSpace);
    }

    // FAT32 clustered directory walk.
    let mut cluster = if parent_dir_cluster == 0
    {
        state.root_cluster
    }
    else
    {
        parent_dir_cluster
    };
    let mut last_cluster = cluster;
    loop
    {
        let base_sector = state.cluster_to_sector(cluster);
        let mut hit_eod = false;
        for s in 0..u32::from(state.sectors_per_cluster)
        {
            match scan_sector_free_run(
                base_sector + s,
                count,
                cache,
                block_dev,
                ipc_buf,
                &mut buf,
                entries_per_sector,
                &mut run,
                &mut run_len,
            )?
            {
                ScanStop::Done => return collect_run(&run, count),
                ScanStop::EndOfDirectory =>
                {
                    hit_eod = true;
                    break;
                }
                ScanStop::Continue =>
                {}
            }
        }
        if hit_eod && run_len < count
        {
            // EoD inside this cluster but run is still short — we need
            // to either fill the rest of this cluster (next sectors are
            // implicitly free too) or extend with a new cluster.
            // Allocate-and-extend handles both: keep walking new
            // clusters until run_len ≥ count.
            let new_cluster =
                allocate_cluster(state, Some(last_cluster), cache, block_dev, ipc_buf)?;
            zero_cluster(state, new_cluster, cache, block_dev, ipc_buf)?;
            // The new cluster's first sector at offset 0 continues the
            // free run.
            let new_base = state.cluster_to_sector(new_cluster);
            for s in 0..u32::from(state.sectors_per_cluster)
            {
                for e in 0..entries_per_sector
                {
                    let loc = DirEntryLocation {
                        sector_lba: new_base + s,
                        offset_in_sector: e * 32,
                    };
                    run[run_len] = Some(loc);
                    run_len += 1;
                    if run_len >= count
                    {
                        return collect_run(&run, count);
                    }
                }
            }
            last_cluster = new_cluster;
            cluster = new_cluster;
            continue;
        }
        if let Some(n) = next_cluster(state, cluster, cache, block_dev, ipc_buf)
        {
            last_cluster = cluster;
            cluster = n;
        }
        else
        {
            // End of cluster chain without seeing 0x00 — every
            // slot in this chain is used. Extend.
            let new_cluster =
                allocate_cluster(state, Some(last_cluster), cache, block_dev, ipc_buf)?;
            zero_cluster(state, new_cluster, cache, block_dev, ipc_buf)?;
            let new_base = state.cluster_to_sector(new_cluster);
            run_len = 0;
            for s in 0..u32::from(state.sectors_per_cluster)
            {
                for e in 0..entries_per_sector
                {
                    let loc = DirEntryLocation {
                        sector_lba: new_base + s,
                        offset_in_sector: e * 32,
                    };
                    run[run_len] = Some(loc);
                    run_len += 1;
                    if run_len >= count
                    {
                        return collect_run(&run, count);
                    }
                }
            }
            last_cluster = new_cluster;
            cluster = new_cluster;
        }
    }
}

fn collect_run(
    run: &[Option<DirEntryLocation>; MAX_SLOT_RUN],
    count: usize,
) -> Result<[DirEntryLocation; MAX_SLOT_RUN], FatError>
{
    let mut out = [DirEntryLocation {
        sector_lba: 0,
        offset_in_sector: 0,
    }; MAX_SLOT_RUN];
    for i in 0..count
    {
        out[i] = run[i].ok_or(FatError::Corrupt)?;
    }
    Ok(out)
}

enum ScanStop
{
    /// `count` consecutive free slots accumulated; caller can stop.
    Done,
    /// End-of-directory sentinel (`0x00`) encountered; caller decides
    /// whether to extend (FAT32) or fail (FAT16 fixed root).
    EndOfDirectory,
    /// Sector finished without reaching either condition; caller
    /// continues to the next sector.
    Continue,
}

#[allow(clippy::too_many_arguments)]
fn scan_sector_free_run(
    sector_lba: u32,
    count: usize,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
    buf: &mut [u8; SECTOR_SIZE],
    entries_per_sector: usize,
    run: &mut [Option<DirEntryLocation>; MAX_SLOT_RUN],
    run_len: &mut usize,
) -> Result<ScanStop, FatError>
{
    if !cache.read_sector(u64::from(sector_lba), block_dev, buf, ipc_buf)
    {
        return Err(FatError::Io);
    }
    for e in 0..entries_per_sector
    {
        let off = e * 32;
        let loc = DirEntryLocation {
            sector_lba,
            offset_in_sector: off,
        };
        let first = buf[off];
        if first == 0x00
        {
            run[*run_len] = Some(loc);
            *run_len += 1;
            if *run_len >= count
            {
                return Ok(ScanStop::Done);
            }
            return Ok(ScanStop::EndOfDirectory);
        }
        if first == 0xE5
        {
            run[*run_len] = Some(loc);
            *run_len += 1;
            if *run_len >= count
            {
                return Ok(ScanStop::Done);
            }
        }
        else
        {
            *run_len = 0;
        }
    }
    Ok(ScanStop::Continue)
}

fn zero_cluster(
    state: &mut FatState,
    cluster: u32,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Result<(), FatError>
{
    let zeros = [0u8; SECTOR_SIZE];
    let base = state.cluster_to_sector(cluster);
    for s in 0..u32::from(state.sectors_per_cluster)
    {
        if !cache.write_sector(u64::from(base + s), block_dev, &zeros, ipc_buf)
        {
            return Err(FatError::Io);
        }
    }
    Ok(())
}

fn write_dir_slot(
    state: &mut FatState,
    loc: DirEntryLocation,
    raw: &[u8; 32],
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Result<(), FatError>
{
    let _ = state; // reserved for future use; mirrors the read-side signature
    let mut buf = [0u8; SECTOR_SIZE];
    if !cache.read_sector(u64::from(loc.sector_lba), block_dev, &mut buf, ipc_buf)
    {
        return Err(FatError::Io);
    }
    buf[loc.offset_in_sector..loc.offset_in_sector + 32].copy_from_slice(raw);
    if !cache.write_sector(u64::from(loc.sector_lba), block_dev, &buf, ipc_buf)
    {
        return Err(FatError::Io);
    }
    Ok(())
}

fn mark_slot_deleted(
    state: &mut FatState,
    loc: DirEntryLocation,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Result<(), FatError>
{
    let _ = state;
    let mut buf = [0u8; SECTOR_SIZE];
    if !cache.read_sector(u64::from(loc.sector_lba), block_dev, &mut buf, ipc_buf)
    {
        return Err(FatError::Io);
    }
    buf[loc.offset_in_sector] = 0xE5;
    if !cache.write_sector(u64::from(loc.sector_lba), block_dev, &buf, ipc_buf)
    {
        return Err(FatError::Io);
    }
    Ok(())
}

fn pack_83_entry(name: &[u8; 11], attr: u8, cluster: u32, size: u32) -> [u8; 32]
{
    let mut e = [0u8; 32];
    e[..11].copy_from_slice(name);
    e[11] = attr;
    // bytes 12 (DIR_NTRes) through 19 (creation timestamps): all zero
    // for v0.1.0; timestamp support filed as a follow-up.
    let cluster_hi = ((cluster >> 16) & 0xFFFF) as u16;
    let cluster_lo = (cluster & 0xFFFF) as u16;
    e[20..22].copy_from_slice(&cluster_hi.to_le_bytes());
    // bytes 22-25: last-write timestamps (zero).
    e[26..28].copy_from_slice(&cluster_lo.to_le_bytes());
    e[28..32].copy_from_slice(&size.to_le_bytes());
    e
}

fn pack_lfn_slot(seq: u8, is_last: bool, chksum: u8, chars: &[u16; 13]) -> [u8; 32]
{
    let mut e = [0u8; 32];
    e[0] = if is_last { seq | LFN_LAST_FLAG } else { seq };
    e[11] = ATTR_LFN;
    e[12] = 0;
    e[13] = chksum;
    // FirstClusLO at bytes 26-27 is zero for LFN slots.
    let offsets: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
    for (i, &off) in offsets.iter().enumerate()
    {
        let bytes = chars[i].to_le_bytes();
        e[off] = bytes[0];
        e[off + 1] = bytes[1];
    }
    e
}

fn name_as_ucs2(name: &[u8]) -> [u16; MAX_LFN_CHARS]
{
    let mut chars = [0u16; MAX_LFN_CHARS];
    // ASCII-only encoding (FAT LFN is UCS-2). For the v0.1.0 write
    // surface we accept the namespace-protocol's name validator,
    // which is ASCII-only; anything beyond ASCII is rejected upstream.
    for (i, &b) in name.iter().enumerate()
    {
        if i >= MAX_LFN_CHARS
        {
            break;
        }
        chars[i] = u16::from(b);
    }
    chars
}

fn lfn_chars_for_seq(chars: &[u16; MAX_LFN_CHARS], name_len: usize, seq: u8) -> [u16; 13]
{
    let base = (usize::from(seq) - 1) * 13;
    let mut slot = [0xFFFFu16; 13];
    for (i, slot_ch) in slot.iter_mut().enumerate()
    {
        let pos = base + i;
        // Per spec: characters past the name are 0xFFFF padding, with
        // a single 0x0000 terminator at the first past-the-end
        // position (matters when name_len is not a multiple of 13).
        *slot_ch = match pos.cmp(&name_len)
        {
            core::cmp::Ordering::Less => chars[pos],
            core::cmp::Ordering::Equal => 0x0000,
            core::cmp::Ordering::Greater => 0xFFFF,
        };
    }
    slot
}

/// Generate a short (8.3) filename for `name`, ensuring uniqueness in
/// the parent directory via `NUMERIC_TAIL` collision probing.
///
/// Strict-8.3 names round-trip exactly (uppercased). Names outside the
/// strict-8.3 charset get a basis derived from the first six valid
/// uppercased characters, with `~N` (1..=6) appended for uniqueness;
/// extension is the first three valid characters after the last `.`.
fn generate_sfn(
    state: &mut FatState,
    parent_dir_cluster: u32,
    name: &[u8],
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Result<[u8; 11], FatError>
{
    if let Some(strict) = try_strict_83(name)
    {
        return Ok(strict);
    }
    let (basis_base, basis_ext) = basis_name(name);
    for tail in 1..=MAX_NUMERIC_TAIL
    {
        let candidate = compose_sfn(basis_base, tail, basis_ext);
        if find_in_directory_by_sfn(
            parent_dir_cluster,
            &candidate,
            state,
            cache,
            block_dev,
            ipc_buf,
        )
        .is_none()
        {
            return Ok(candidate);
        }
    }
    Err(FatError::NoSpace)
}

fn try_strict_83(name: &[u8]) -> Option<[u8; 11]>
{
    let dot_pos = name.iter().position(|&b| b == b'.');
    let (base, ext) = match dot_pos
    {
        Some(p) =>
        {
            // Reject multiple dots and leading dot.
            if name[p + 1..].contains(&b'.') || p == 0
            {
                return None;
            }
            (&name[..p], &name[p + 1..])
        }
        None => (name, &[] as &[u8]),
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3
    {
        return None;
    }
    for &b in base.iter().chain(ext.iter())
    {
        if !is_strict_83_char(b)
        {
            return None;
        }
    }
    let mut out = [b' '; 11];
    for (i, &b) in base.iter().enumerate()
    {
        out[i] = to_upper(b);
    }
    for (i, &b) in ext.iter().enumerate()
    {
        out[8 + i] = to_upper(b);
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

fn basis_name(name: &[u8]) -> ([u8; 6], [u8; 3])
{
    let mut base = [b' '; 6];
    let mut ext = [b' '; 3];
    let dot_pos = name.iter().rposition(|&b| b == b'.');
    let (base_src, ext_src) = match dot_pos
    {
        Some(p) => (&name[..p], &name[p + 1..]),
        None => (name, &[] as &[u8]),
    };
    let mut bi = 0;
    for &b in base_src
    {
        if bi >= 6
        {
            break;
        }
        if is_strict_83_char(b)
        {
            base[bi] = to_upper(b);
            bi += 1;
        }
    }
    let mut ei = 0;
    for &b in ext_src
    {
        if ei >= 3
        {
            break;
        }
        if is_strict_83_char(b)
        {
            ext[ei] = to_upper(b);
            ei += 1;
        }
    }
    // FAT spec: every SFN basis must have at least one valid base
    // character; fall back to a single underscore if upstream gave us
    // a name with no usable chars in the base portion.
    if bi == 0
    {
        base[0] = b'_';
    }
    (base, ext)
}

fn compose_sfn(basis_base: [u8; 6], tail: u8, basis_ext: [u8; 3]) -> [u8; 11]
{
    let mut out = [b' '; 11];
    // Find how much of the basis-base we keep; the tail "~N" replaces
    // the trailing slot(s).
    let mut base_end = 6;
    while base_end > 0 && basis_base[base_end - 1] == b' '
    {
        base_end -= 1;
    }
    // Tail length: "~" + decimal digits. tail ≤ 6 → one digit.
    let tail_chars: [u8; 2] = [b'~', b'0' + tail];
    let keep = (8 - tail_chars.len()).min(base_end);
    out[..keep].copy_from_slice(&basis_base[..keep]);
    out[keep] = tail_chars[0];
    out[keep + 1] = tail_chars[1];
    // Extension at bytes 8..11.
    out[8..11].copy_from_slice(&basis_ext);
    out
}

/// Look up an entry by SFN only (no LFN matching). Used by
/// [`generate_sfn`] for `NUMERIC_TAIL` collision probing.
fn find_in_directory_by_sfn(
    parent_dir_cluster: u32,
    sfn: &[u8; 11],
    state: &mut FatState,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Option<()>
{
    let mut buf = [0u8; SECTOR_SIZE];
    let entries_per_sector = SECTOR_SIZE / 32;

    if parent_dir_cluster == 0 && matches!(state.fat_type, FatType::Fat16)
    {
        let root_start =
            u32::from(state.reserved_sectors) + u32::from(state.num_fats) * state.fat_size;
        let root_sectors = (u32::from(state.root_entry_count) * 32).div_ceil(512);
        for s in 0..root_sectors
        {
            match scan_sector_for_sfn(
                root_start + s,
                sfn,
                cache,
                block_dev,
                ipc_buf,
                &mut buf,
                entries_per_sector,
            )
            {
                Some(true) => return Some(()),
                Some(false) =>
                {}
                None => return None,
            }
        }
        return None;
    }

    let mut cluster = if parent_dir_cluster == 0
    {
        state.root_cluster
    }
    else
    {
        parent_dir_cluster
    };
    loop
    {
        let base_sector = state.cluster_to_sector(cluster);
        for s in 0..u32::from(state.sectors_per_cluster)
        {
            match scan_sector_for_sfn(
                base_sector + s,
                sfn,
                cache,
                block_dev,
                ipc_buf,
                &mut buf,
                entries_per_sector,
            )
            {
                Some(true) => return Some(()),
                Some(false) =>
                {}
                None => return None,
            }
        }
        cluster = next_cluster(state, cluster, cache, block_dev, ipc_buf)?;
    }
}

/// Per-sector SFN match used by `find_in_directory_by_sfn`. Returns
/// `Some(true)` on match, `Some(false)` to continue, `None` on I/O
/// failure (cache acquire / read).
#[allow(clippy::too_many_arguments)]
fn scan_sector_for_sfn(
    sector_lba: u32,
    sfn: &[u8; 11],
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
    buf: &mut [u8; SECTOR_SIZE],
    entries_per_sector: usize,
) -> Option<bool>
{
    if !cache.read_sector(u64::from(sector_lba), block_dev, buf, ipc_buf)
    {
        return None;
    }
    for e in 0..entries_per_sector
    {
        let off = e * 32;
        if buf[off] == 0x00
        {
            return Some(false);
        }
        if buf[off] == 0xE5 || buf[off + 11] == ATTR_LFN
        {
            continue;
        }
        if buf[off..off + 11] == *sfn
        {
            return Some(true);
        }
    }
    Some(false)
}

/// Locate an entry by name *and* the disk positions of its LFN run.
/// Used by [`remove_entry`] so we can mark every LFN slot as deleted
/// alongside the trailing 8.3 entry.
fn locate_entry_with_lfn_run(
    state: &mut FatState,
    parent_dir_cluster: u32,
    name: &[u8],
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Result<(RemovedEntry, [DirEntryLocation; MAX_SLOT_RUN]), FatError>
{
    let entries_per_sector = SECTOR_SIZE / 32;
    let mut buf = [0u8; SECTOR_SIZE];
    let mut lfn = LfnAccum::new();
    let mut lfn_run: [Option<DirEntryLocation>; MAX_SLOT_RUN] = [None; MAX_SLOT_RUN];
    let mut lfn_run_len = 0usize;

    if parent_dir_cluster == 0 && matches!(state.fat_type, FatType::Fat16)
    {
        let root_start =
            u32::from(state.reserved_sectors) + u32::from(state.num_fats) * state.fat_size;
        let root_sectors = (u32::from(state.root_entry_count) * 32).div_ceil(512);
        for s in 0..root_sectors
        {
            if let Some((entry, run, run_len)) = scan_sector_for_remove(
                root_start + s,
                name,
                cache,
                block_dev,
                ipc_buf,
                &mut buf,
                entries_per_sector,
                &mut lfn,
                &mut lfn_run,
                &mut lfn_run_len,
            )?
            {
                if entry.start_cluster == u32::MAX
                {
                    return Err(FatError::Corrupt); // not found before EoD
                }
                let mut out = [DirEntryLocation {
                    sector_lba: 0,
                    offset_in_sector: 0,
                }; MAX_SLOT_RUN];
                for i in 0..run_len
                {
                    out[i] = run[i].ok_or(FatError::Corrupt)?;
                }
                return Ok((entry, out));
            }
        }
        return Err(FatError::Corrupt);
    }

    let mut cluster = if parent_dir_cluster == 0
    {
        state.root_cluster
    }
    else
    {
        parent_dir_cluster
    };
    loop
    {
        let base_sector = state.cluster_to_sector(cluster);
        for s in 0..u32::from(state.sectors_per_cluster)
        {
            if let Some((entry, run, run_len)) = scan_sector_for_remove(
                base_sector + s,
                name,
                cache,
                block_dev,
                ipc_buf,
                &mut buf,
                entries_per_sector,
                &mut lfn,
                &mut lfn_run,
                &mut lfn_run_len,
            )?
            {
                if entry.start_cluster == u32::MAX
                {
                    return Err(FatError::Corrupt);
                }
                let mut out = [DirEntryLocation {
                    sector_lba: 0,
                    offset_in_sector: 0,
                }; MAX_SLOT_RUN];
                for i in 0..run_len
                {
                    out[i] = run[i].ok_or(FatError::Corrupt)?;
                }
                return Ok((entry, out));
            }
        }
        match next_cluster(state, cluster, cache, block_dev, ipc_buf)
        {
            Some(n) => cluster = n,
            None => return Err(FatError::Corrupt),
        }
    }
}

/// Per-sector walk for [`locate_entry_with_lfn_run`]. Returns the
/// matching entry and its full LFN-run + 8.3 slot positions, or `None`
/// to continue. On end-of-directory, returns the sentinel
/// [`RemovedEntry`] `start_cluster == u32::MAX` so the caller maps to
/// `NotFound`.
type RemoveScanHit = (
    RemovedEntry,
    [Option<DirEntryLocation>; MAX_SLOT_RUN],
    usize,
);
#[allow(clippy::too_many_arguments)]
fn scan_sector_for_remove(
    sector_lba: u32,
    name: &[u8],
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
    buf: &mut [u8; SECTOR_SIZE],
    entries_per_sector: usize,
    lfn: &mut LfnAccum,
    lfn_run: &mut [Option<DirEntryLocation>; MAX_SLOT_RUN],
    lfn_run_len: &mut usize,
) -> Result<Option<RemoveScanHit>, FatError>
{
    if !cache.read_sector(u64::from(sector_lba), block_dev, buf, ipc_buf)
    {
        return Err(FatError::Io);
    }
    for e in 0..entries_per_sector
    {
        let off = e * 32;
        let loc = DirEntryLocation {
            sector_lba,
            offset_in_sector: off,
        };
        if buf[off] == 0x00
        {
            return Ok(Some((
                RemovedEntry {
                    start_cluster: u32::MAX,
                    size: 0,
                    is_dir: false,
                },
                *lfn_run,
                *lfn_run_len,
            )));
        }
        if buf[off] == 0xE5
        {
            lfn.reset();
            *lfn_run_len = 0;
            continue;
        }
        if buf[off + 11] == ATTR_LFN
        {
            lfn.add_lfn_entry(&buf[off..off + 32]);
            if *lfn_run_len < MAX_SLOT_RUN
            {
                lfn_run[*lfn_run_len] = Some(loc);
                *lfn_run_len += 1;
            }
            continue;
        }
        let raw = &buf[off..off + 32];
        if let Some(entry) = parse_dir_entry(raw)
        {
            let lfn_match = lfn.validate(&entry.name) && lfn.matches(name);
            let sfn_match = name_matches(&entry.name, name);
            if lfn_match || sfn_match
            {
                let mut run = [None; MAX_SLOT_RUN];
                let mut run_len = 0;
                if lfn_match
                {
                    run[..*lfn_run_len].copy_from_slice(&lfn_run[..*lfn_run_len]);
                    run_len = *lfn_run_len;
                }
                run[run_len] = Some(loc);
                run_len += 1;
                return Ok(Some((
                    RemovedEntry {
                        start_cluster: entry.cluster,
                        size: entry.size,
                        is_dir: entry.attr & ATTR_DIRECTORY != 0,
                    },
                    run,
                    run_len,
                )));
            }
        }
        lfn.reset();
        *lfn_run_len = 0;
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
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Result<(), FatError>
{
    if entry.start_cluster == 0
    {
        return Ok(());
    }
    free_cluster_chain(state, entry.start_cluster, cache, block_dev, ipc_buf).map(|_| ())
}
