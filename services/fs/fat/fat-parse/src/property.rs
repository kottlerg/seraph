// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/fat-parse/src/property.rs

//! The contract of this crate's parsers of hostile input as one property over
//! any input, [`fat_holds`], which the fuzz target `fat` (`xtask/fuzz/targets`)
//! drives, the replay test of the checked-in inputs under `fuzz/fat/` runs on
//! every `cargo xtask test`, and the proofs of `lib.rs` check on every input
//! up to their bounds (docs/testing.md § Fuzzing, § Bounded verification).
//!
//! The `fatfs` driver hands this crate bytes it read from a disk: sector 0,
//! which [`parse_bpb_geometry`] decodes; FAT sectors, whose entries
//! [`read_fat_entry`] reads and [`write_fat_entry`] writes in place; and
//! directory sectors, whose 32-byte slots [`parse_dir_entry`],
//! [`LfnAccum`], [`RemoveRunScan`], [`FreeRunScan`] and [`tail_of`] read. A
//! client's name reaches [`name_matches`], [`LfnAccum::matches`] and
//! [`encode_lfn`]. Each check states the contract from the Microsoft FAT
//! specification by its own reading of the bytes, never through the code it
//! checks, save that a check of a scan's step runs the steps it is built
//! from, which checks of their own hold to their contracts.

use alloc::vec::Vec;

use crate::{
    ATTR_LFN, BpbError, BpbGeometry, DIR_ENTRIES_MAX, FatType, FreeRunScan, LfnAccum,
    MAX_LFN_CHARS, MAX_LFN_UTF8, MAX_NUMERIC_TAIL, MAX_SLOT_RUN, MIN_SECTOR_SIZE, RemoveRunScan,
    RemoveStep, SlotRun, TailSet, cluster_to_sector, compose_tailed_name, encode_lfn,
    fat_entry_location, is_data_cluster, lfn_checksum, name_matches, pack_lfn_slot,
    parse_bpb_geometry, parse_dir_entry, read_fat_entry, tail_of, utf8_char, utf8_step,
    write_fat_entry,
};

/// Bytes of one directory slot.
const SLOT_BYTES: usize = 32;

/// Most slots of one long name's run: 20 slots of 13 characters hold the
/// 255 of the longest name.
const MAX_LFN_SLOTS: usize = MAX_SLOT_RUN - 1;

/// Code units of one long-name slot.
const SLOT_UNITS: usize = 13;

/// Byte offsets in a long-name slot of its 13 UCS-2 characters (Microsoft
/// FAT specification § 7: `LDIR_Name1`, `LDIR_Name2`, `LDIR_Name3`).
const SLOT_UNIT_OFFSETS: [usize; SLOT_UNITS] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];

/// The fewest clusters of a FAT32 volume, and one past the most of a FAT16
/// one (Microsoft FAT specification § 3.5).
const FAT32_MIN_CLUSTERS: u64 = 65_525;

/// The fewest clusters of a FAT16 volume.
const FAT16_MIN_CLUSTERS: u64 = 4085;

/// Check the parsers' contract on `input`: read as sector 0 of a volume on a
/// device whose blocks are the size the sector declares, 512 or 4096 bytes,
/// and whose partition holds no bound, exactly the declared sectors, or one
/// fewer; as a FAT sector, an entry of each width at every offset, read and
/// written in place; and as a directory sector, its slots walked as the
/// driver walks them, with a removal scan for the first listed entry's
/// names, a free-run scan, and the numeric tails of its short names.
///
/// # Panics
///
/// When a parser breaks its contract on `input`: a defect of the parser.
pub fn fat_holds(input: &[u8])
{
    let declared = Fields::read(input);
    let block = declared.map_or(0, |f| u32::from(f.bytes_per_sector));
    let total = declared.map_or(0, |f| u64::from(f.total_sectors));
    for block in [block, 512, 4096]
    {
        for partition in [u64::MAX, total, total.saturating_sub(1)]
        {
            bpb_holds(input, block, partition);
            // The first and last data clusters, the ones on either side of the
            // data region, and one the input names.
            for cluster in cluster_probes(input, total)
            {
                geometry_cluster_holds(input, block, partition, cluster);
            }
        }
    }
    for fat_type in [FatType::Fat16, FatType::Fat32]
    {
        for offset in 0..=input.len().saturating_add(1)
        {
            let value = le32(input, offset).map_or(0x0FFF_FFFF, |v| !v);
            fat_entry_holds(input, fat_type, offset, value);
        }
    }
    // The long-name encoding of the input's first bytes, the encoding's
    // character read at each offset, and one step of the long-name assembly
    // at each even offset of the first 128 bytes:
    // two code units, a buffer of 8 bytes, and a length and position the
    // offset's bytes name.
    encode_holds(input.get(..MAX_LFN_UTF8).unwrap_or(input));
    for start in 0..input.len()
    {
        utf8_char_holds(input.get(start..).unwrap_or_default());
    }
    for at in (0..input.len().min(128)).step_by(2)
    {
        let units = [le16(input, at), le16(input, at.wrapping_add(2))];
        let count = units.iter().take_while(|u| u.is_some()).count();
        let units = units.map(|u| u.unwrap_or(0));
        let mut out = [0u8; 8];
        for (dst, &b) in out.iter_mut().zip(input.iter().skip(at))
        {
            *dst = b;
        }
        let byte = |i: usize| usize::from(input.get(i).copied().unwrap_or(0));
        utf8_step_holds(
            units.get(..count).unwrap_or_default(),
            out,
            byte(at) % 9,
            byte(at.wrapping_add(1)) % 9,
        );
    }
    directory_holds(input);
}

// ── BIOS Parameter Block ────────────────────────────────────────────────────

/// The BPB fields of sector 0 as the specification places them (§ 3.1, § 3.3).
#[derive(Clone, Copy)]
struct Fields
{
    signature: bool,
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    num_fats: u8,
    root_entry_count: u16,
    total_sectors: u32,
    fat_size: u32,
    root_cluster: u32,
    fsinfo: u16,
}

impl Fields
{
    /// The fields of the first [`MIN_SECTOR_SIZE`] bytes of `sector`, which
    /// hold every one of them; `None` when `sector` is shorter.
    fn read(sector: &[u8]) -> Option<Self>
    {
        let head = sector.get(..MIN_SECTOR_SIZE)?;
        let byte = |at: usize| head.get(at).copied().unwrap_or(0);
        let word = |at: usize| le16(head, at).unwrap_or(0);
        let dword = |at: usize| le32(head, at).unwrap_or(0);
        Some(Self {
            signature: byte(510) == 0x55 && byte(511) == 0xAA,
            bytes_per_sector: word(11),
            sectors_per_cluster: byte(13),
            reserved_sectors: word(14),
            num_fats: byte(16),
            root_entry_count: word(17),
            total_sectors: match word(19)
            {
                0 => dword(32),
                small => u32::from(small),
            },
            fat_size: match word(22)
            {
                0 => dword(36),
                small => u32::from(small),
            },
            root_cluster: dword(44),
            fsinfo: word(48),
        })
    }

    /// The geometry the fields give a volume whose sector size is one the
    /// specification permits and whose clusters are not empty; `None`
    /// otherwise.
    fn layout(&self) -> Option<Layout>
    {
        let shift = match self.bytes_per_sector
        {
            512 => 9,
            1024 => 10,
            2048 => 11,
            4096 => 12,
            _ => return None,
        };
        if self.sectors_per_cluster == 0
        {
            return None;
        }
        let bps = u64::from(self.bytes_per_sector);
        // The root directory's 32-byte entries, in whole sectors (§ 3.5).
        let root_dir_sectors = (u64::from(self.root_entry_count) * 32)
            .wrapping_add(bps.wrapping_sub(1))
            .wrapping_shr(shift);
        // Each term is below 2^40, so the sum fits a u64.
        let data_start = u64::from(self.reserved_sectors)
            .wrapping_add(u64::from(self.num_fats).wrapping_mul(u64::from(self.fat_size)))
            .wrapping_add(root_dir_sectors);
        let data_sectors = u64::from(self.total_sectors).saturating_sub(data_start);
        // The specification's cluster count (§ 3.5): the data region's whole
        // clusters, its sectors over the cluster size, a shift for the
        // powers of two the specification permits (§ 3.1, `BPB_SecPerClus`).
        // A volume of another cluster size is refused before its count is
        // read.
        let clusters = data_sectors.wrapping_shr(self.sectors_per_cluster.trailing_zeros());
        // The data region holds at least `k` clusters.
        let at_least = |k: u64| clusters >= k;
        let fat32 = at_least(FAT32_MIN_CLUSTERS);
        let (entry_shift, max_clusters) = if fat32
        {
            (2, 0x0FFF_FFF5u64)
        }
        else
        {
            (1, 0xFFF5)
        };
        let fat_entries = u64::from(self.fat_size)
            .wrapping_shl(shift)
            .wrapping_shr(entry_shift);
        // Every cluster 2..2 + clusters has an entry in one FAT copy:
        // clusters <= entries - 2, so fewer than entries - 1 of them.
        let capacity = fat_entries
            .checked_sub(1)
            .is_some_and(|bound| !at_least(bound))
            && !at_least(max_clusters.saturating_add(1));
        // A FAT32 root names a data cluster: 2 <= root < clusters + 2.
        let root = u64::from(self.root_cluster);
        let root_inside = !fat32 || root.checked_sub(1).is_some_and(|k| k >= 1 && at_least(k));
        Some(Layout {
            data_start,
            clusters,
            fat12: !at_least(FAT16_MIN_CLUSTERS),
            fat32,
            capacity,
            root_inside,
        })
    }
}

/// What [`Fields::layout`] derives.
#[derive(Clone, Copy)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one flag a rule of the specification, read together by the judge"
)]
struct Layout
{
    data_start: u64,
    clusters: u64,
    fat12: bool,
    fat32: bool,
    capacity: bool,
    root_inside: bool,
}

/// Check [`parse_bpb_geometry`] on `sector` read from a device of `block`-byte
/// blocks whose partition holds `partition` of them: it accepts exactly the
/// volumes the specification's rules allow and this driver reads (a FAT16 or
/// FAT32 volume of the device's sector size whose FAT holds an entry for each
/// cluster, whose FAT32 root lies in the data region, and which fits its
/// partition), names a broken rule when it refuses, and decodes the fields as
/// the specification places them.
pub(crate) fn bpb_holds(sector: &[u8], block: u32, partition: u64)
{
    let result = parse_bpb_geometry(sector, block, partition);
    let Some(fields) = Fields::read(sector)
    else
    {
        assert!(
            matches!(result, Err(BpbError::UnsupportedSectorSize)),
            "a sector 0 shorter than a BPB is refused as a sector size"
        );
        return;
    };
    let layout = fields.layout();
    let geometry_ok = layout.is_some_and(|l| {
        fields.num_fats != 0
            && fields.reserved_sectors != 0
            && fields.sectors_per_cluster.is_power_of_two()
            && u32::try_from(l.data_start).is_ok()
            && !l.fat12
            && l.capacity
            && l.root_inside
    });
    let accepted = fields.signature
        && geometry_ok
        && u32::from(fields.bytes_per_sector) == block
        && u64::from(fields.total_sectors) <= partition;
    match result
    {
        Ok(geometry) =>
        {
            assert!(accepted, "a BPB that breaks a rule is accepted");
            if let Some(layout) = layout
            {
                geometry_matches(&geometry, &fields, &layout);
            }
        }
        Err(error) =>
        {
            assert!(!accepted, "a BPB that keeps every rule is refused");
            let explained = match error
            {
                BpbError::BadSignature => !fields.signature,
                BpbError::ZeroDivisor =>
                {
                    fields.bytes_per_sector == 0 || fields.sectors_per_cluster == 0
                }
                BpbError::UnsupportedSectorSize =>
                {
                    !matches!(fields.bytes_per_sector, 512 | 1024 | 2048 | 4096)
                        || u32::from(fields.bytes_per_sector) != block
                }
                BpbError::Fat12 => layout.is_some_and(|l| l.fat12),
                BpbError::BadGeometry => layout.is_some_and(|l| {
                    fields.num_fats == 0
                        || fields.reserved_sectors == 0
                        || !fields.sectors_per_cluster.is_power_of_two()
                        || l.data_start > u64::from(u32::MAX)
                        || !l.capacity
                        || !l.root_inside
                        || u64::from(fields.total_sectors) > partition
                }),
            };
            assert!(explained, "a BPB is refused for a rule it keeps");
        }
    }
}

/// An accepted geometry holds the BPB's fields and what the specification
/// derives from them.
fn geometry_matches(geometry: &BpbGeometry, fields: &Fields, layout: &Layout)
{
    assert_eq!(geometry.bytes_per_sector, fields.bytes_per_sector);
    assert_eq!(geometry.sectors_per_cluster, fields.sectors_per_cluster);
    assert_eq!(geometry.reserved_sectors, fields.reserved_sectors);
    assert_eq!(geometry.num_fats, fields.num_fats);
    assert_eq!(geometry.root_entry_count, fields.root_entry_count);
    assert_eq!(geometry.fat_size, fields.fat_size);
    assert_eq!(geometry.total_sectors, fields.total_sectors);
    assert_eq!(u64::from(geometry.data_start_sector), layout.data_start);
    assert_eq!(u64::from(geometry.total_clusters), layout.clusters);
    assert_eq!(matches!(geometry.fat_type, FatType::Fat32), layout.fat32);
    let root = if layout.fat32 { fields.root_cluster } else { 0 };
    assert_eq!(geometry.root_cluster, root);
    let fsinfo = (layout.fat32
        && fields.fsinfo != 0
        && fields.fsinfo != 0xFFFF
        && fields.fsinfo < fields.reserved_sectors)
        .then_some(u32::from(fields.fsinfo));
    assert_eq!(geometry.fsinfo_sector, fsinfo);
}

/// The clusters [`fat_holds`] places on a volume whose BPB declares
/// `total` sectors: 0 to 3, the clusters around the end of a data region
/// as large as the volume, and one the input names at byte 0.
fn cluster_probes(input: &[u8], total: u64) -> [u32; 8]
{
    let last = u32::try_from(total).unwrap_or(u32::MAX);
    [
        0,
        1,
        2,
        3,
        last,
        last.saturating_add(1),
        last.saturating_add(2),
        le32(input, 0).unwrap_or(0),
    ]
}

/// Check, on a volume whose sector 0 is `sector` and which
/// [`parse_bpb_geometry`] accepts, that `cluster` lies in the data region
/// exactly when it is one of its clusters, and that a data cluster's FAT
/// entry lies inside the first FAT copy and its sectors inside the volume
/// and the partition.
pub(crate) fn geometry_cluster_holds(sector: &[u8], block: u32, partition: u64, cluster: u32)
{
    let Ok(geometry) = parse_bpb_geometry(sector, block, partition)
    else
    {
        return;
    };
    let clusters = u64::from(geometry.total_clusters);
    let inside = (2..clusters.wrapping_add(2)).contains(&u64::from(cluster));
    assert_eq!(is_data_cluster(cluster, geometry.total_clusters), inside);
    if !inside
    {
        return;
    }
    let shift = u64::from(geometry.bytes_per_sector).trailing_zeros();
    let bps = u64::from(geometry.bytes_per_sector);
    let entry_bytes: u64 = match geometry.fat_type
    {
        FatType::Fat16 => 2,
        FatType::Fat32 => 4,
    };
    let offset = u64::from(cluster).wrapping_mul(entry_bytes);
    let location = fat_entry_location(
        geometry.fat_type,
        geometry.reserved_sectors,
        geometry.bytes_per_sector,
        cluster,
    );
    assert!(location.is_some(), "a data cluster has a FAT entry");
    if let Some((fat_sector, at)) = location
    {
        let reserved = u64::from(geometry.reserved_sectors);
        let entry_sector = reserved.wrapping_add(offset.wrapping_shr(shift));
        assert_eq!(u64::from(fat_sector), entry_sector);
        assert_eq!(u64::try_from(at).ok(), Some(offset & bps.wrapping_sub(1)));
        assert!(
            entry_sector < reserved.wrapping_add(u64::from(geometry.fat_size)),
            "a data cluster's FAT entry lies inside the first FAT copy"
        );
    }
    let spc = u64::from(geometry.sectors_per_cluster);
    let first = cluster_to_sector(
        geometry.data_start_sector,
        geometry.sectors_per_cluster,
        cluster,
    );
    let expected = u64::from(geometry.data_start_sector)
        .wrapping_add(u64::from(cluster).wrapping_sub(2).wrapping_mul(spc));
    assert_eq!(u64::from(first), expected);
    let end = expected.wrapping_add(spc);
    assert!(
        end <= u64::from(geometry.total_sectors) && end <= partition,
        "a data cluster lies inside the volume and its partition"
    );
}

// ── FAT entries ─────────────────────────────────────────────────────────────

/// Check the FAT entry of `fat_type` at byte `offset` of `sector`: it is
/// read, a FAT16 entry whole and a FAT32 one without its top four bits,
/// exactly when it lies inside the sector; and `value` written there reads
/// back, the FAT32 entry's top four bits and every other byte kept, while a
/// write outside the sector changes nothing.
pub(crate) fn fat_entry_holds(sector: &[u8], fat_type: FatType, offset: usize, value: u32)
{
    let (width, mask) = match fat_type
    {
        FatType::Fat16 => (2, 0xFFFF),
        FatType::Fat32 => (4, 0x0FFF_FFFF),
    };
    let fits = offset
        .checked_add(width)
        .is_some_and(|end| end <= sector.len());
    let read = read_fat_entry(sector, fat_type, offset);
    if fits
    {
        let entry = sector
            .iter()
            .skip(offset)
            .take(width)
            .rev()
            .fold(0u32, |acc, &b| acc.wrapping_shl(8) | u32::from(b));
        assert_eq!(read, Some(entry & mask));
    }
    else
    {
        assert_eq!(read, None);
    }
    // The write, on a copy of the bytes from one before the entry: the
    // entry keeps its place against the sector's end, so it fits the copy
    // exactly when it fits the sector.
    let start = offset.saturating_sub(1).min(sector.len());
    let mut window = [0u8; 6];
    let mut len = 0usize;
    for (dst, &src) in window.iter_mut().zip(sector.iter().skip(start))
    {
        *dst = src;
        len = len.wrapping_add(1);
    }
    let before = window;
    let at = offset.wrapping_sub(start);
    let wrote = window
        .get_mut(..len)
        .and_then(|w| write_fat_entry(w, fat_type, at, value));
    assert_eq!(wrote.is_some(), fits);
    for (i, (&now, &was)) in window.iter().zip(&before).enumerate()
    {
        let in_entry = fits && (at..at.wrapping_add(width)).contains(&i);
        if !in_entry
        {
            assert_eq!(now, was, "a FAT write changes a byte outside its entry");
        }
    }
    if fits
    {
        let back = window
            .get(..len)
            .and_then(|w| read_fat_entry(w, fat_type, at));
        assert_eq!(back, Some(value & mask));
        if matches!(fat_type, FatType::Fat32)
        {
            let top = at.wrapping_add(3);
            assert_eq!(
                window.get(top).map(|b| b & 0xF0),
                before.get(top).map(|b| b & 0xF0),
                "a FAT32 write keeps the entry's reserved bits"
            );
        }
    }
}

// ── Directory slots ─────────────────────────────────────────────────────────

/// The specification's checksum of a short name (§ 7.2): each byte added to
/// the sum rotated right by one.
fn spec_checksum(name: &[u8; 11]) -> u8
{
    name.iter()
        .fold(0u8, |sum, &b| sum.rotate_right(1).wrapping_add(b))
}

/// `bytes` without its trailing spaces.
fn trimmed(bytes: &[u8]) -> &[u8]
{
    let len = bytes
        .iter()
        .rposition(|&b| b != b' ')
        .map_or(0, |last| last.wrapping_add(1));
    bytes.get(..len).unwrap_or_default()
}

/// The name a short entry lists under: its base and, when it has one, a dot
/// and its extension, each without its padding and in lower case when its
/// `DIR_NTRes` flag (`0x08` base, `0x10` extension) says so.
fn short_display(name: &[u8; 11], nt_case: u8) -> ([u8; 12], usize)
{
    let (base, ext) = name.split_at(8);
    let fold = |b: u8, flag: u8| {
        if nt_case & flag != 0
        {
            b.to_ascii_lowercase()
        }
        else
        {
            b
        }
    };
    let ext = trimmed(ext);
    let bytes = trimmed(base)
        .iter()
        .map(|&b| fold(b, 0x08))
        .chain((!ext.is_empty()).then_some(b'.'))
        .chain(ext.iter().map(|&b| fold(b, 0x10)));
    let mut out = [0u8; 12];
    let mut len = 0usize;
    for (dst, b) in out.iter_mut().zip(bytes)
    {
        *dst = b;
        len = len.wrapping_add(1);
    }
    (out, len)
}

/// Check [`parse_dir_entry`] on one slot: it skips exactly the end marker,
/// a deleted slot and a slot whose attribute holds the volume-label bit (a
/// long-name slot among them), decodes the rest as the specification places
/// the fields (§ 6), and lists such an entry under its short name; and the
/// slot's checksum is the specification's.
pub(crate) fn dir_entry_holds(raw: &[u8; SLOT_BYTES])
{
    let mut name = [0u8; 11];
    name.copy_from_slice(raw.first_chunk::<11>().unwrap_or(&[0; 11]));
    assert_eq!(lfn_checksum(&name), spec_checksum(&name));
    let skipped = raw[0] == 0x00 || raw[0] == 0xE5 || raw[11] & 0x08 != 0;
    let parsed = parse_dir_entry(raw);
    assert_eq!(parsed.is_none(), skipped);
    let Some(entry) = parsed
    else
    {
        return;
    };
    assert_eq!(entry.name, name);
    assert_eq!(entry.attr, raw[11]);
    assert_eq!(entry.nt_case, raw[12]);
    assert_eq!(
        entry.cluster,
        u32::from_le_bytes([raw[26], raw[27], raw[20], raw[21]])
    );
    assert_eq!(
        entry.size,
        u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]])
    );
    assert_eq!(entry.lfn_len, 0);
    let (shown, shown_len) = short_display(&name, raw[12]);
    let shown = shown.get(..shown_len).unwrap_or_default();
    // A buffer one byte past the longest short name, and one the slot sizes
    // shorter, which takes the name's start.
    let mut out = [0u8; 13];
    let written = entry.write_display_name(&mut out, usize::from(raw[30]));
    assert_eq!(out.get(..written), Some(shown));
    assert!(
        out.iter().skip(written).all(|&b| b == 0),
        "a short name is written past its end"
    );
    let room = usize::from(raw[31]).checked_rem(out.len()).unwrap_or(0);
    let mut short = [0u8; 13];
    let written = entry.write_display_name(short.get_mut(..room).unwrap_or_default(), 255);
    assert_eq!(written, room.min(shown.len()));
    assert_eq!(short.get(..written), shown.get(..written));
    name_matches_holds(&name, shown);
}

/// Check [`name_matches`]: `component` matches the short name `entry`
/// exactly when it spells it, a base of up to eight bytes before its first
/// dot and an extension of up to three after it, each folded to upper case
/// and padded with spaces.
pub(crate) fn name_matches_holds(entry: &[u8; 11], component: &[u8])
{
    let (base, ext) = match component.iter().position(|&b| b == b'.')
    {
        Some(dot) => (
            component.get(..dot).unwrap_or_default(),
            component.get(dot.wrapping_add(1)..).unwrap_or_default(),
        ),
        None => (component, &[][..]),
    };
    let (entry_base, entry_ext) = entry.split_at(8);
    let spells = |field: &[u8], part: &[u8]| {
        part.len() <= field.len()
            && field
                .iter()
                .enumerate()
                .all(|(i, &b)| b == part.get(i).map_or(b' ', u8::to_ascii_uppercase))
    };
    let spelled = spells(entry_base, base) && spells(entry_ext, ext);
    assert_eq!(name_matches(entry, component), spelled);
}

// ── Long names ──────────────────────────────────────────────────────────────

/// A copy of `acc`, for a check to step while it keeps the state before.
fn copy_lfn(acc: &LfnAccum) -> LfnAccum
{
    LfnAccum {
        chars: acc.chars,
        len: acc.len,
        chksum: acc.chksum,
        last_seq: acc.last_seq,
        saw_last: acc.saw_last,
        active: acc.active,
    }
}

/// Run `check` on the name position `probe` names, or on every position
/// when it names none. A proof passes any position (`kani::any`), which
/// checks every position in one problem with no loop over the 255 of them;
/// a run passes none.
fn at_positions(probe: Option<usize>, mut check: impl FnMut(usize))
{
    match probe
    {
        Some(pos) =>
        {
            if pos < MAX_LFN_CHARS
            {
                check(pos);
            }
        }
        None => (0..MAX_LFN_CHARS).for_each(check),
    }
}

/// Whether `a` and `b` are the same state, their units compared at the
/// positions `probe` names ([`at_positions`]).
fn same_lfn(a: &LfnAccum, b: &LfnAccum, probe: Option<usize>) -> bool
{
    let mut same_units = true;
    at_positions(probe, |pos| {
        same_units &= a.chars.get(pos) == b.chars.get(pos);
    });
    same_units
        && a.len == b.len
        && a.chksum == b.chksum
        && a.last_seq == b.last_seq
        && a.saw_last == b.saw_last
        && a.active == b.active
}

/// The states an accumulator stands in: it holds a run exactly when it has
/// seen the run's first slot, a name of at most [`MAX_LFN_CHARS`] units,
/// and a run's last sequence number lies in `1..=20`.
pub(crate) fn lfn_invariant(acc: &LfnAccum) -> bool
{
    acc.active == acc.saw_last
        && acc.len <= MAX_LFN_CHARS
        && (!acc.active || (1..=20).contains(&usize::from(acc.last_seq)))
}

/// Whether `acc` holds no run.
fn lfn_empty(acc: &LfnAccum) -> bool
{
    !acc.active && !acc.saw_last && acc.len == 0 && acc.last_seq == 0 && acc.chksum == 0
}

/// The 13 UCS-2 code units of a long-name slot, in name order.
fn slot_units(raw: &[u8; SLOT_BYTES]) -> [u16; SLOT_UNITS]
{
    SLOT_UNIT_OFFSETS.map(|at| le16(raw, at).unwrap_or(0))
}

/// Whether `unit` ends a long name: `0x0000` terminates it and `0xFFFF`
/// pads the slot after it (§ 7).
fn ends_name(unit: u16) -> bool
{
    unit == 0x0000 || unit == 0xFFFF
}

/// Check one step of [`LfnAccum::add_lfn_entry`] from `before`, a state in
/// the invariant: a deleted slot, or one whose sequence number lies outside
/// `1..=20`, empties the accumulator; a slot flagged as a run's first
/// (`0x40`) starts a run of its sequence number, its checksum and the name
/// up to its first ending unit, at most `seq * 13` and 255 units; a slot
/// numbered one below the last, with the run's checksum, continues it,
/// ending the name at its own first ending unit when that comes first and
/// keeping every unit outside its 13; any other slot empties the
/// accumulator. The slot's units before its ending unit stand at their
/// place in the name, and the state stays in the invariant. Units are
/// checked at the positions `probe` names ([`at_positions`]).
pub(crate) fn lfn_step_holds(before: &LfnAccum, raw: &[u8; SLOT_BYTES], probe: Option<usize>)
{
    assert!(
        lfn_invariant(before),
        "a check stepped from outside the invariant"
    );
    let mut after = copy_lfn(before);
    after.add_lfn_entry(raw);
    assert!(lfn_invariant(&after), "a step leaves the invariant");
    let seq = raw[0] & 0x3F;
    let first = raw[0] & 0x40 != 0;
    let continues = !first
        && before.saw_last
        && raw[13] == before.chksum
        && before.last_seq == seq.wrapping_add(1);
    if raw[0] == 0xE5 || !(1..=20).contains(&seq) || !(first || continues)
    {
        assert!(
            lfn_empty(&after),
            "a slot that neither starts nor continues a run keeps one"
        );
        return;
    }
    assert!(after.active && after.saw_last, "a run's slot leaves no run");
    assert_eq!(after.last_seq, seq);
    assert_eq!(after.chksum, raw[13]);
    let units = slot_units(raw);
    let base = usize::from(seq).wrapping_sub(1).wrapping_mul(SLOT_UNITS);
    let ending = units
        .iter()
        .position(|&u| ends_name(u))
        .unwrap_or(SLOT_UNITS);
    // A slot with no ending unit leaves the name's end where it was.
    let ends_at = if ending < SLOT_UNITS
    {
        base.wrapping_add(ending)
    }
    else
    {
        usize::MAX
    };
    let len = if first
    {
        usize::from(seq)
            .wrapping_mul(SLOT_UNITS)
            .min(MAX_LFN_CHARS)
            .min(ends_at)
    }
    else
    {
        before.len.min(ends_at)
    };
    assert_eq!(after.len, len);
    at_positions(probe, |pos| {
        let now = after.chars.get(pos);
        let in_slot = pos.checked_sub(base).filter(|&j| j < SLOT_UNITS);
        if let Some(j) = in_slot.filter(|&j| j < ending)
        {
            assert_eq!(now, units.get(j), "a slot's unit misplaced");
        }
        if in_slot.is_none() && continues
        {
            assert_eq!(
                now,
                before.chars.get(pos),
                "a continuing slot changes a unit outside it"
            );
        }
    });
}

/// Check [`LfnAccum::validate`]: a run is valid for the short name `sfn`
/// exactly when it is complete, down to sequence number 1, and carries the
/// specification's checksum of `sfn`.
pub(crate) fn validate_holds(acc: &LfnAccum, sfn: &[u8; 11])
{
    let expected =
        acc.active && acc.saw_last && acc.last_seq == 1 && spec_checksum(sfn) == acc.chksum;
    assert_eq!(acc.validate(sfn), expected);
}

/// The scalar value `units` starts with and the code units it takes, by
/// RFC 2781 § 2.2; `None` when `units` is empty or starts with a surrogate
/// that no other completes.
fn decode_utf16(units: &[u16]) -> Option<(u32, usize)>
{
    let high = *units.first()?;
    if !(0xD800..=0xDFFF).contains(&high)
    {
        return Some((u32::from(high), 1));
    }
    let low = *units.get(1)?;
    if high > 0xDBFF || !(0xDC00..=0xDFFF).contains(&low)
    {
        return None;
    }
    let scalar = ((u32::from(high & 0x3FF) << 10) | u32::from(low & 0x3FF)).wrapping_add(0x1_0000);
    Some((scalar, 2))
}

/// The UTF-8 bytes of the scalar value `scalar`, by RFC 3629 § 3.
fn encode_utf8(scalar: u32) -> ([u8; 4], usize)
{
    #[expect(
        clippy::cast_possible_truncation,
        reason = "each byte is masked or shifted to its eight bits first"
    )]
    let byte = |bits: u32| bits as u8;
    let tail = |shift: u32| byte(0x80 | (scalar.wrapping_shr(shift) & 0x3F));
    match scalar
    {
        0..=0x7F => ([byte(scalar), 0, 0, 0], 1),
        0x80..=0x7FF => ([byte(0xC0 | scalar.wrapping_shr(6)), tail(0), 0, 0], 2),
        0x800..=0xFFFF => (
            [byte(0xE0 | scalar.wrapping_shr(12)), tail(6), tail(0), 0],
            3,
        ),
        _ => (
            [
                byte(0xF0 | scalar.wrapping_shr(18)),
                tail(12),
                tail(6),
                tail(0),
            ],
            4,
        ),
    }
}

/// The UTF-8 form of the code units `units` into `out`, its length; `None`
/// when a surrogate stands unpaired or the form does not fit `out`.
fn utf16_to_utf8(units: &[u16], out: &mut [u8]) -> Option<usize>
{
    let mut at = 0usize;
    let mut pos = 0usize;
    while let Some(rest) = units.get(at..).filter(|rest| !rest.is_empty())
    {
        let (scalar, width) = decode_utf16(rest)?;
        let (bytes, len) = encode_utf8(scalar);
        let end = pos.checked_add(len)?;
        out.get_mut(pos..end)?
            .copy_from_slice(bytes.get(..len).unwrap_or_default());
        at = at.wrapping_add(width);
        pos = end;
    }
    Some(pos)
}

/// Check one step of [`LfnAccum::assemble_utf8`] on `units`, into the first
/// `len` bytes of `out` at `pos`: it writes the UTF-8 form of the character
/// `units` starts with at `pos` and returns the units it takes and the
/// position past its bytes, or, for an empty `units`, an unpaired
/// surrogate or a form past the buffer, returns `None`; it writes no other
/// byte.
pub(crate) fn utf8_step_holds(units: &[u16], out: [u8; 8], len: usize, pos: usize)
{
    let mut after = out;
    let step = after
        .get_mut(..len.min(out.len()))
        .and_then(|buf| utf8_step(units, buf, pos));
    let expected = decode_utf16(units).and_then(|(scalar, width)| {
        let (bytes, n) = encode_utf8(scalar);
        let end = pos
            .checked_add(n)
            .filter(|&end| end <= len.min(out.len()))?;
        Some((width, end, bytes, n))
    });
    assert_eq!(step, expected.map(|(width, end, ..)| (width, end)));
    for (i, (&now, &was)) in after.iter().zip(&out).enumerate()
    {
        match expected
        {
            Some((_, end, bytes, _)) if (pos..end).contains(&i) =>
            {
                assert_eq!(Some(&now), bytes.get(i.wrapping_sub(pos)));
            }
            _ => assert_eq!(now, was, "a step writes past its character"),
        }
    }
}

/// Check [`LfnAccum::assemble_utf8`] into a buffer of `room` bytes: it
/// writes the UTF-8 form of the run's name, the first `len` units, and
/// returns its length, or `None` when a surrogate stands unpaired or the
/// form does not fit. `N` bytes hold the forms, at least the UTF-8 form of
/// the run's name.
pub(crate) fn assemble_holds<const N: usize>(acc: &LfnAccum, room: usize)
{
    let units = acc.chars.get(..acc.len).unwrap_or(&acc.chars);
    let mut expected = [0u8; N];
    let expected_len = utf16_to_utf8(units, &mut expected);
    let mut out = [0u8; N];
    let room = room.min(N);
    let got = acc.assemble_utf8(out.get_mut(..room).unwrap_or_default());
    match expected_len
    {
        Some(n) if n <= room =>
        {
            assert_eq!(got, Some(n));
            assert!(
                out.iter().take(n).eq(expected.iter().take(n)),
                "the assembly writes another form"
            );
        }
        _ => assert_eq!(got, None),
    }
}

/// Check [`LfnAccum::matches`]: a complete run matches `name` exactly when
/// its name's UTF-8 form equals `name` with ASCII letters folded. `N` bytes
/// hold the form, at least the UTF-8 form of the run's name.
pub(crate) fn match_holds<const N: usize>(acc: &LfnAccum, name: &[u8])
{
    let units = acc.chars.get(..acc.len).unwrap_or(&acc.chars);
    let mut expected = [0u8; N];
    let expected_len = utf16_to_utf8(units, &mut expected);
    let complete = acc.active && acc.saw_last && acc.last_seq == 1;
    let same = expected_len
        .and_then(|n| expected.get(..n))
        .is_some_and(|form| {
            form.len() == name.len()
                && form
                    .iter()
                    .zip(name)
                    .all(|(a, b)| a.eq_ignore_ascii_case(b))
        });
    assert_eq!(acc.matches(name), complete && same);
}

/// Check [`utf8_char`] on `rest`: it gives the character `rest` starts
/// with and its width, by core's UTF-8 check (`core::str::from_utf8`) of its
/// first four bytes, the most one character holds, and `None` when `rest`
/// starts with no UTF-8 character, an empty `rest` included.
pub(crate) fn utf8_char_holds(rest: &[u8])
{
    let window = rest.get(..4).unwrap_or(rest);
    let valid = match core::str::from_utf8(window)
    {
        Ok(text) => text,
        Err(error) => window
            .get(..error.valid_up_to())
            .and_then(|prefix| core::str::from_utf8(prefix).ok())
            .unwrap_or_default(),
    };
    let expected = valid.chars().next().map(|ch| (ch, ch.len_utf8()));
    assert_eq!(utf8_char(rest), expected, "a character was misread");
}

/// Check [`encode_lfn`] on `name`: it encodes a UTF-8 `name`, read a
/// character at a time by [`utf8_char`] (checked by [`utf8_char_holds`]),
/// whose UTF-16 form takes at most [`MAX_LFN_CHARS`] code units and holds no
/// unit a long name's slots take as its end (U+0000, the byte 0x00 in UTF-8,
/// or U+FFFF, the bytes EF BF BF), and refuses every other name; the units it
/// gives read back, by RFC 2781 and RFC 3629, as `name`. Returns the units
/// and their count for a name it encodes. `N` bytes hold the read-back form,
/// at least the UTF-8 form of a name the units can give.
pub(crate) fn encode_contract_holds<const N: usize>(
    name: &[u8],
) -> Option<([u16; MAX_LFN_CHARS], usize)>
{
    let mut units = [0u16; MAX_LFN_CHARS];
    let Some(count) = encode_lfn(name, &mut units)
    else
    {
        let ends = name.contains(&0x00) || name.windows(3).any(|w| matches!(w, [0xEF, 0xBF, 0xBF]));
        // A character takes two code units when its UTF-8 form takes four.
        let needed = name.iter().fold(0usize, |n, &b| {
            n.wrapping_add(usize::from(b & 0xC0 != 0x80))
                .wrapping_add(usize::from(b >= 0xF0))
        });
        let mut at = 0usize;
        let mut utf8 = true;
        while let Some(rest) = name.get(at..).filter(|rest| !rest.is_empty())
        {
            let Some((_, width)) = utf8_char(rest)
            else
            {
                utf8 = false;
                break;
            };
            at = at.wrapping_add(width);
        }
        assert!(
            !utf8 || ends || needed > MAX_LFN_CHARS,
            "a storable name is refused"
        );
        return None;
    };
    let encoded = units.get(..count).unwrap_or_default();
    assert!(
        !encoded.iter().copied().any(ends_name),
        "a name is encoded with a unit that ends it"
    );
    let mut back = [0u8; N];
    assert_eq!(utf16_to_utf8(encoded, &mut back), Some(name.len()));
    assert!(
        back.iter().take(name.len()).eq(name.iter()),
        "a name's units read back as another name"
    );
    Some((units, count))
}

/// Check [`encode_lfn`] on `name` ([`encode_contract_holds`]), and that the
/// units, packed into their slots ([`pack_holds`]) and read back through the
/// accumulator, give `name` again.
pub(crate) fn encode_holds(name: &[u8])
{
    let Some((units, count)) = encode_contract_holds::<MAX_LFN_UTF8>(name)
    else
    {
        return;
    };
    let Some(acc) = pack_holds(units.get(..count).unwrap_or_default())
    else
    {
        return;
    };
    let mut out = [0u8; MAX_LFN_UTF8];
    let len = acc.assemble_utf8(&mut out);
    assert_eq!(len, Some(name.len()));
    assert_eq!(out.get(..name.len()), Some(name));
    assert!(acc.matches(name), "a packed run does not match its name");
}

/// Check [`pack_lfn_slot`] on one slot: it packs slot `seq` of the name
/// `units` exactly when `seq` is one of the 20 slots a name of
/// [`MAX_LFN_CHARS`] takes, and lays the slot out as the specification does
/// (§ 7): the sequence byte, with the last-slot flag when `is_last`, the
/// long-name attribute, the checksum, a zero first cluster, and the 13
/// characters from position `(seq - 1) * 13` at bytes 1, 14 and 28, a
/// position past the name holding one `0x0000` terminator and then `0xFFFF`
/// padding.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`is_last` is the last-slot bit of the slot it checks, as `pack_lfn_slot` takes it"
)]
pub(crate) fn pack_slot_holds(seq: u8, is_last: bool, chksum: u8, units: &[u16])
{
    let slot = pack_lfn_slot(seq, is_last, chksum, units);
    if !(1..=20).contains(&seq)
    {
        assert_eq!(slot, None);
        return;
    }
    assert!(slot.is_some(), "a slot of a name is refused");
    let Some(slot) = slot
    else
    {
        return;
    };
    let flag = if is_last { 0x40 } else { 0 };
    assert_eq!(slot[0], seq | flag);
    assert_eq!(slot[11], ATTR_LFN);
    assert_eq!(slot[12], 0);
    assert_eq!(slot[13], chksum);
    assert_eq!((slot[26], slot[27]), (0, 0));
    let base = usize::from(seq).wrapping_sub(1).wrapping_mul(SLOT_UNITS);
    for j in 0..SLOT_UNITS
    {
        let at = match j
        {
            0..=4 => 1usize.wrapping_add(j.wrapping_mul(2)),
            5..=10 => 14usize.wrapping_add(j.wrapping_sub(5).wrapping_mul(2)),
            _ => 28usize.wrapping_add(j.wrapping_sub(11).wrapping_mul(2)),
        };
        let pos = base.wrapping_add(j);
        let expected = match units.get(pos)
        {
            Some(&unit) => unit,
            None if pos == units.len() => 0x0000,
            None => 0xFFFF,
        };
        let got = slot
            .get(at..at.wrapping_add(2))
            .and_then(<[u8]>::first_chunk::<2>)
            .map(|&b| u16::from_le_bytes(b));
        assert_eq!(got, Some(expected), "a character is packed out of place");
    }
}

/// Check [`pack_lfn_slot`] on a storable name's `units` (at most
/// [`MAX_LFN_CHARS`], none a unit that ends a name): every slot of the run
/// is packed, and the run, read back through the accumulator in disk order,
/// validates for its short name and holds `units` as its name. Returns the
/// accumulator; `None` for no units.
pub(crate) fn pack_holds(units: &[u16]) -> Option<LfnAccum>
{
    if units.is_empty()
    {
        return None;
    }
    let count = units.len();
    let sfn = *b"LONGNA~1TXT";
    let chksum = lfn_checksum(&sfn);
    let slots = count.div_ceil(SLOT_UNITS);
    let mut acc = LfnAccum::new();
    for seq in (1..=slots).rev()
    {
        let seq = u8::try_from(seq).unwrap_or(0);
        pack_slot_holds(seq, usize::from(seq) == slots, chksum, units);
        let raw = pack_lfn_slot(seq, usize::from(seq) == slots, chksum, units);
        assert!(raw.is_some(), "a slot of a storable name is refused");
        if let Some(raw) = raw
        {
            acc.add_lfn_entry(&raw);
        }
    }
    assert!(acc.validate(&sfn), "a packed run does not validate");
    assert_eq!(acc.len, count);
    assert!(
        acc.chars.iter().take(count).eq(units.iter()),
        "a packed run reads back other units"
    );
    Some(acc)
}

// ── Slot scans ──────────────────────────────────────────────────────────────

/// A copy of `run`.
fn copy_run(run: &SlotRun<u32>) -> SlotRun<u32>
{
    SlotRun {
        slots: run.slots,
        len: run.len,
    }
}

/// Whether `run` holds the places of `before` and then `loc`, as a run of
/// at most [`MAX_SLOT_RUN`] keeps them (compared place by place, so no
/// buffer compare reads an empty run's dangling address).
fn is_pushed(run: &[u32], before: &[u32], loc: u32) -> bool
{
    run.iter().copied().eq(before
        .iter()
        .copied()
        .chain(core::iter::once(loc))
        .take(MAX_SLOT_RUN))
}

/// Whether `run` holds the same places as `other`.
fn same_run(run: &[u32], other: &[u32]) -> bool
{
    run.iter().eq(other.iter())
}

/// Check one step of [`RemoveRunScan::step`] from `before`, for the slot
/// `raw` at `loc` and the name `name`: an end marker ends the scan and
/// changes nothing; a deleted slot empties it; a long-name slot steps the
/// accumulator and records its place, from a fresh run on a run's first slot,
/// leaving the last place for the short entry; a short entry that `name`
/// matches, by the run's long name when the run is valid for it or by its
/// short name, is found with its first cluster, the run's places then the
/// entry's when the run is valid for it, the entry's alone otherwise; any
/// other slot empties the scan. The accumulator's units are compared at the
/// positions `probe` names ([`at_positions`]).
pub(crate) fn remove_step_holds(
    before: &RemoveRunScan<u32>,
    raw: &[u8; SLOT_BYTES],
    loc: u32,
    name: &[u8],
    probe: Option<usize>,
)
{
    let mut after = RemoveRunScan {
        lfn: copy_lfn(&before.lfn),
        slots: copy_run(&before.slots),
    };
    let step = after.step(raw, loc, name);
    let run_before = before.slots.as_slice();
    if raw[0] == 0x00
    {
        assert!(
            matches!(step, RemoveStep::EndOfDir),
            "an end marker does not end the scan"
        );
        assert!(same_lfn(&after.lfn, &before.lfn, probe) && same_run(after.run(), run_before));
        return;
    }
    if raw[0] != 0xE5 && raw[11] == 0x0F
    {
        assert!(
            matches!(step, RemoveStep::Continue),
            "a long-name slot ends the scan"
        );
        let mut lfn = copy_lfn(&before.lfn);
        lfn.add_lfn_entry(raw);
        assert!(
            same_lfn(&after.lfn, &lfn, probe),
            "a long-name slot steps the run otherwise"
        );
        let recorded = if raw[0] & 0x40 != 0
        {
            is_pushed(after.run(), &[], loc)
        }
        else if run_before.len() < MAX_LFN_SLOTS
        {
            is_pushed(after.run(), run_before, loc)
        }
        else
        {
            same_run(after.run(), run_before)
        };
        assert!(recorded, "a long-name slot's place is recorded otherwise");
        return;
    }
    let found = (raw[0] != 0xE5)
        .then(|| parse_dir_entry(raw))
        .flatten()
        .and_then(|entry| {
            let valid = before.lfn.validate(&entry.name);
            ((valid && before.lfn.matches(name)) || name_matches(&entry.name, name))
                .then_some((entry.cluster, valid))
        });
    if let Some((cluster, valid)) = found
    {
        assert!(
            matches!(step, RemoveStep::Found { cluster: c } if c == cluster),
            "a matching entry is not found with its cluster"
        );
        let run = if valid { run_before } else { &[] };
        assert!(
            is_pushed(after.run(), run, loc),
            "a found entry's places are not its run's and its own"
        );
    }
    else
    {
        assert!(
            matches!(step, RemoveStep::Continue),
            "a slot that does not match ends the scan"
        );
        assert!(
            lfn_empty(&after.lfn) && after.run().is_empty(),
            "the scan keeps a run"
        );
    }
}

/// The states a free-run scan stands in: it looks for a run of 1 to
/// [`MAX_SLOT_RUN`] slots, holds no more than that, and takes the marker
/// slot only after a complete run that crossed the end of the directory.
pub(crate) fn free_invariant(scan: &FreeRunScan<u32>) -> bool
{
    (1..=MAX_SLOT_RUN).contains(&scan.count)
        && scan.slots.len <= scan.count
        && (scan.end_marker.is_none() || (scan.slots.len >= scan.count && scan.past_end))
}

/// Check one step of [`FreeRunScan::step`] from `before`, a state in the
/// invariant, for the slot at `loc` whose first byte is `first`: once the
/// run is complete, the step changes nothing but taking `loc` as the marker
/// slot of a run that crossed the end, and needs no more slots; before that,
/// an end marker puts the scan past the end, a free slot (deleted, or any
/// past the end) extends the run and any other restarts it, and the scan
/// needs no more slots once the run is complete before the end.
pub(crate) fn free_step_holds(before: &FreeRunScan<u32>, first: u8, loc: u32)
{
    assert!(
        free_invariant(before),
        "a check stepped from outside the invariant"
    );
    let mut after = FreeRunScan {
        slots: copy_run(&before.slots),
        count: before.count,
        past_end: before.past_end,
        end_marker: before.end_marker,
    };
    let done = after.step(first, loc);
    assert!(free_invariant(&after), "a step leaves the invariant");
    assert_eq!(after.count, before.count);
    if before.slots.len >= before.count
    {
        assert!(done, "a complete run asks for another slot");
        assert!(
            same_run(after.run(), before.run()),
            "a complete run changes"
        );
        assert_eq!(after.past_end, before.past_end);
        let marker = if before.past_end && before.end_marker.is_none()
        {
            Some(loc)
        }
        else
        {
            before.end_marker
        };
        assert_eq!(after.end_marker, marker);
        return;
    }
    let past_end = before.past_end || first == 0x00;
    assert_eq!(after.past_end, past_end);
    assert_eq!(after.end_marker, None);
    if past_end || first == 0xE5
    {
        assert!(
            is_pushed(after.run(), before.run(), loc),
            "a free slot does not extend the run"
        );
    }
    else
    {
        assert!(after.run().is_empty(), "a slot in use keeps the run");
    }
    assert_eq!(done, after.slots.len >= after.count && !past_end);
}

/// Check [`tail_of`]: a tail read from `sfn` against `basis` is one the
/// scheme gives (`1..=`[`MAX_NUMERIC_TAIL`]) and composes back to `sfn`.
pub(crate) fn tail_read_holds(sfn: &[u8; 11], basis: &[u8; 11])
{
    if let Some(read) = tail_of(sfn, basis)
    {
        assert!(
            (1..=MAX_NUMERIC_TAIL).contains(&read),
            "a tail outside the scheme is read"
        );
        assert_eq!(compose_tailed_name(basis, read), Some(*sfn));
    }
}

/// Check [`compose_tailed_name`]: a tail outside `1..=`[`MAX_NUMERIC_TAIL`]
/// composes no name; a tail inside it composes the base's leading bytes,
/// as many as fit before `~` and the tail's digits within eight bytes, then
/// `~`, then the tail's decimal digits with no leading zero, then spaces, with
/// the extension kept. The digits are read back by multiplication, so no
/// division judges the one it checks.
pub(crate) fn compose_holds(basis: &[u8; 11], tail: u32)
{
    let composed = compose_tailed_name(basis, tail);
    if !(1..=MAX_NUMERIC_TAIL).contains(&tail)
    {
        assert_eq!(composed, None);
        return;
    }
    assert!(composed.is_some(), "a tail of the scheme composes no name");
    let Some(name) = composed
    else
    {
        return;
    };
    assert_eq!(name.get(8..), basis.get(8..), "the extension is not kept");
    let short = trimmed(name.get(..8).unwrap_or_default());
    let tilde = short.iter().rposition(|&b| b == b'~');
    assert!(tilde.is_some(), "a composed name holds no tail");
    let Some(tilde) = tilde
    else
    {
        return;
    };
    let digits = short.get(tilde.wrapping_add(1)..).unwrap_or_default();
    assert!(
        !digits.is_empty()
            && digits.first() != Some(&b'0')
            && digits.iter().all(u8::is_ascii_digit),
        "a tail's digits are not decimal"
    );
    let value = digits.iter().fold(0u64, |acc, &d| {
        acc.wrapping_mul(10)
            .wrapping_add(u64::from(d.wrapping_sub(b'0')))
    });
    assert_eq!(value, u64::from(tail));
    let base = trimmed(basis.get(..8).unwrap_or_default());
    let keep = base.len().min(7usize.wrapping_sub(digits.len()));
    assert_eq!(tilde, keep, "the base keeps more or fewer bytes than fit");
    assert_eq!(short.get(..keep), base.get(..keep));
    assert!(
        name.iter()
            .take(8)
            .skip(keep.wrapping_add(1).wrapping_add(digits.len()))
            .all(|&b| b == b' '),
        "a composed name is not padded with spaces"
    );
}

/// Check that a tail composed with `basis` reads back from the name.
pub(crate) fn tail_round_trip_holds(basis: &[u8; 11], tail: u32)
{
    if let Some(name) = compose_tailed_name(basis, tail)
    {
        assert_eq!(tail_of(&name, basis), Some(tail));
    }
}

// ── The directory walk ─────────────────────────────────────────────────────

/// One short entry a directory walk lists.
struct Listed
{
    /// Its slot.
    slot: usize,
    name: [u8; 11],
    nt_case: u8,
    /// The first slot of the long-name run valid for it.
    run_start: Option<usize>,
    /// The UTF-8 form of that run's name, when it has one.
    long: Option<Vec<u8>>,
}

/// The first slot of the long-name run valid for the short entry `name` at
/// slot `at` of `slots`, read as the specification lays a run out (§ 7):
/// the latest slot flagged as a run's first among the long-name slots right
/// before the entry, numbered `n` in `1..=20`, then `n - 1` down to 1 in the
/// slots after it, the last right before the entry, each carrying the
/// specification's checksum of `name`.
fn run_start(slots: &[[u8; SLOT_BYTES]], at: usize, name: &[u8; 11]) -> Option<usize>
{
    let lfn_slot = |raw: &[u8; SLOT_BYTES]| raw[11] == 0x0F && raw[0] != 0xE5;
    let before = slots.get(..at)?;
    let start = before
        .iter()
        .rposition(|raw| !lfn_slot(raw) || raw[0] & 0x40 != 0)
        .filter(|&s| before.get(s).is_some_and(lfn_slot))?;
    let n = usize::from(before.get(start)?[0] & 0x3F);
    let sum = spec_checksum(name);
    let run = before.get(start..)?;
    let valid = (1..=20).contains(&n)
        && run.len() == n
        && run
            .iter()
            .enumerate()
            .all(|(i, raw)| usize::from(raw[0] & 0x3F) == n.wrapping_sub(i) && raw[13] == sum);
    valid.then_some(start)
}

/// The code units of the name of the run in `run` (its slots in disk order,
/// the last numbered 1), before its first ending unit, at most
/// [`MAX_LFN_CHARS`].
fn run_units(run: &[[u8; SLOT_BYTES]]) -> Vec<u16>
{
    let mut units: Vec<u16> = run.iter().rev().flat_map(slot_units).collect();
    let end = units
        .iter()
        .position(|&u| ends_name(u))
        .unwrap_or(units.len())
        .min(MAX_LFN_CHARS);
    units.truncate(end);
    units
}

/// Walk `input` as a directory sector, as the driver lists a directory: an
/// end marker ends it, a deleted slot drops the run, a long-name slot steps
/// it, and a short entry takes the run's name when the run is valid for it.
/// Each step, the run's validity and name against the slots' own reading,
/// the listed names, a removal scan for the first entry's names, a free-run
/// scan and the entries' numeric tails are checked.
fn directory_holds(input: &[u8])
{
    let slots = input.as_chunks::<SLOT_BYTES>().0;
    let mut acc = LfnAccum::new();
    let mut listed: Vec<Listed> = Vec::new();
    for (at, raw) in slots.iter().enumerate()
    {
        dir_entry_holds(raw);
        if raw[0] == 0x00
        {
            break;
        }
        if raw[0] == 0xE5
        {
            acc.reset();
            assert!(lfn_empty(&acc), "a reset keeps a run");
            continue;
        }
        if raw[11] == 0x0F
        {
            lfn_step_holds(&acc, raw, None);
            acc.add_lfn_entry(raw);
            continue;
        }
        if let Some(entry) = parse_dir_entry(raw)
        {
            validate_holds(&acc, &entry.name);
            let start = run_start(slots, at, &entry.name);
            assert_eq!(acc.validate(&entry.name), start.is_some());
            let mut long = None;
            if let Some(start) = start
            {
                let units = run_units(slots.get(start..at).unwrap_or_default());
                assert_eq!(acc.chars.get(..acc.len), Some(units.as_slice()));
                let mut form = [0u8; MAX_LFN_UTF8];
                let len = utf16_to_utf8(&units, &mut form);
                long = len.and_then(|n| form.get(..n)).map(Vec::from);
                assemble_holds::<MAX_LFN_UTF8>(&acc, MAX_LFN_UTF8);
                match_holds::<MAX_LFN_UTF8>(&acc, long.as_deref().unwrap_or_default());
                assemble_holds::<MAX_LFN_UTF8>(&acc, usize::from(raw[30]));
                match_holds::<MAX_LFN_UTF8>(&acc, &entry.name);
                listed_name_holds(&acc, &entry, long.as_deref());
                if let Some(long) = &long
                {
                    encode_holds(long);
                }
            }
            listed.push(Listed {
                slot: at,
                name: entry.name,
                nt_case: entry.nt_case,
                run_start: start,
                long,
            });
        }
        acc.reset();
    }
    if let Some(first) = listed.first()
    {
        let (short, len) = short_display(&first.name, first.nt_case);
        remove_scan_holds(slots, &listed, short.get(..len).unwrap_or_default());
        if let Some(long) = &first.long
        {
            remove_scan_holds(slots, &listed, long);
        }
        tails_hold(input, &listed, &first.name);
    }
    let count = usize::from(input.first().copied().unwrap_or(0))
        .checked_rem(MAX_SLOT_RUN)
        .unwrap_or(0)
        .wrapping_add(1);
    free_scan_holds(slots, count);
}

/// The name an entry with a valid run lists under: the run's name when its
/// UTF-8 form fits the 255 bytes a protocol name carries, its short name
/// otherwise.
fn listed_name_holds(acc: &LfnAccum, entry: &crate::DirEntry, long: Option<&[u8]>)
{
    let mut entry = *entry;
    if let Some(len) = acc.assemble_utf8(&mut entry.lfn)
    {
        entry.lfn_len = u16::try_from(len).unwrap_or(0);
    }
    let mut out = [0u8; MAX_LFN_UTF8];
    let written = entry.write_display_name(&mut out, 255);
    let (short, short_len) = short_display(&entry.name, entry.nt_case);
    let expected = match long
    {
        Some(long) if !long.is_empty() && long.len() <= 255 => long,
        _ => short.get(..short_len).unwrap_or_default(),
    };
    assert_eq!(out.get(..written), Some(expected));
}

/// Drive a removal scan for `name` over `slots`, checking each step: it
/// finds the first listed entry `name` matches, by its valid run's name
/// (ASCII letters folded) or its short name, with the run's slots then the
/// entry's, and otherwise ends at the end marker or the sector's end.
fn remove_scan_holds(slots: &[[u8; SLOT_BYTES]], listed: &[Listed], name: &[u8])
{
    let expected = listed.iter().find(|entry| {
        entry
            .long
            .as_deref()
            .is_some_and(|long| long.eq_ignore_ascii_case(name))
            || name_matches(&entry.name, name)
    });
    let mut scan = RemoveRunScan::<u32>::new();
    let mut outcome = None;
    for (at, raw) in slots.iter().enumerate()
    {
        let loc = u32::try_from(at).unwrap_or(u32::MAX);
        remove_step_holds(&scan, raw, loc, name, None);
        match scan.step(raw, loc, name)
        {
            RemoveStep::Continue =>
            {}
            RemoveStep::EndOfDir =>
            {
                outcome = Some(None);
                break;
            }
            RemoveStep::Found { .. } =>
            {
                outcome = Some(Some(at));
                break;
            }
        }
    }
    let found = outcome.flatten();
    assert_eq!(found, expected.map(|entry| entry.slot));
    if let Some(entry) = expected
    {
        let first = entry.run_start.unwrap_or(entry.slot);
        let run: Vec<u32> = (first..=entry.slot)
            .map(|at| u32::try_from(at).unwrap_or(u32::MAX))
            .collect();
        assert_eq!(scan.run(), run.as_slice());
    }
}

/// Drive a free-run scan for `count` slots over `slots`, checking each step:
/// it takes the first `count` consecutive free slots (deleted, or at or past
/// the end marker), and, when they reach past the marker, the slot after
/// them as the new marker.
fn free_scan_holds(slots: &[[u8; SLOT_BYTES]], count: usize)
{
    let end = slots
        .iter()
        .position(|raw| raw[0] == 0x00)
        .unwrap_or(slots.len());
    let free = |at: usize| at >= end || slots.get(at).is_some_and(|raw| raw[0] == 0xE5);
    let run = (0..slots.len()).find(|&start| {
        start
            .checked_add(count)
            .is_some_and(|stop| stop <= slots.len() && (start..stop).all(free))
    });
    let mut scan = FreeRunScan::<u32>::new(count);
    let mut done_at = None;
    for (at, raw) in slots.iter().enumerate()
    {
        let loc = u32::try_from(at).unwrap_or(u32::MAX);
        free_step_holds(&scan, raw[0], loc);
        if scan.step(raw[0], loc)
        {
            done_at = Some(at);
            break;
        }
    }
    let Some(start) = run
    else
    {
        assert!(!scan.run_complete(), "a run is found where none is free");
        return;
    };
    assert!(scan.run_complete(), "a free run is missed");
    let last = start.wrapping_add(count).wrapping_sub(1);
    let expected: Vec<u32> = (start..=last)
        .map(|at| u32::try_from(at).unwrap_or(u32::MAX))
        .collect();
    assert_eq!(scan.run(), expected.as_slice());
    if last >= end
    {
        let marker = last.wrapping_add(1);
        let has_marker = marker < slots.len();
        assert_eq!(done_at, has_marker.then_some(marker));
        assert_eq!(
            scan.end_marker(),
            has_marker.then(|| u32::try_from(marker).unwrap_or(u32::MAX))
        );
    }
    else
    {
        assert_eq!(done_at, Some(last));
        assert_eq!(scan.end_marker(), None);
    }
}

/// The numeric tails of the listed short names against `basis`: each read
/// and composed back ([`tail_read_holds`], [`compose_holds`], with a tail `input` names at each
/// entry's slot), and the lowest a [`TailSet`] of them finds free.
fn tails_hold(input: &[u8], listed: &[Listed], basis: &[u8; 11])
{
    let Some(mut set) = TailSet::try_new()
    else
    {
        return;
    };
    let mut used: Vec<u32> = Vec::new();
    for entry in listed
    {
        let tail = le32(input, entry.slot.wrapping_mul(SLOT_BYTES).wrapping_add(28)).unwrap_or(0)
            % (MAX_NUMERIC_TAIL + 2);
        tail_read_holds(&entry.name, basis);
        compose_holds(basis, tail);
        tail_round_trip_holds(basis, tail);
        set.note(&entry.name, basis);
        used.extend(tail_of(&entry.name, basis));
    }
    let lowest = (1..=DIR_ENTRIES_MAX + 1).find(|t| !used.contains(t));
    assert_eq!(set.lowest_free(), lowest);
}

/// The little-endian `u16` at `at` in `bytes`.
fn le16(bytes: &[u8], at: usize) -> Option<u16>
{
    bytes
        .get(at..at.checked_add(2)?)?
        .first_chunk::<2>()
        .map(|b| u16::from_le_bytes(*b))
}

/// The little-endian `u32` at `at` in `bytes`.
fn le32(bytes: &[u8], at: usize) -> Option<u32>
{
    bytes
        .get(at..at.checked_add(4)?)?
        .first_chunk::<4>()
        .map(|b| u32::from_le_bytes(*b))
}
