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

use crate::bpb::{FatState, SECTOR_SIZE};
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
