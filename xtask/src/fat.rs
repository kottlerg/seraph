// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/fat.rs

//! The FAT file system of each partition `mkdisk` formats, written with its contents from a
//! host directory tree in one pass.
//!
//! The variant follows from the volume's cluster count, by the Microsoft FAT specification's
//! type rule: [`geometry`] lays a volume out as FAT16 when that gives it 4085 to 65524
//! clusters and as FAT32 when that gives it 65525 or more, and refuses a size neither admits.
//! Clusters are [`CLUSTER_BYTES`] and the data region starts on a cluster boundary. Each file's
//! and directory's clusters are contiguous, allocated in the order of the tree, and every
//! timestamp is 1980-01-01 00:00:00, so two writes of one tree are byte-identical. A name that
//! is an upper-case 8.3 name is stored as its short entry alone; any other takes a long-name
//! run and a short name unique in its directory.
//!
//! The encodings the writer shares with the `fatfs` service (the FAT entries, the long-name
//! slots and their checksum, and the short names' numeric tails) are `fatfs-parse`'s. In-tree
//! code replaces a registry crate here (`docs/coding-standards.md` § Dependencies).

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fat_parse::FatType;

use crate::error::{Context, Result, bail, ensure};

/// Bytes per cluster: one page of the `fatfs` service's page-granular sector cache. With the
/// data region on a cluster boundary, a file's data within a cluster is one page of the
/// partition.
pub const CLUSTER_BYTES: u32 = 4096;

/// FAT copies on a volume.
const FAT_COUNT: u32 = 2;

/// Root-directory entries of a FAT16 volume, the count the specification recommends.
const FAT16_ROOT_ENTRIES: u16 = 512;

/// Fewest reserved sectors of a FAT16 volume: the boot sector.
const FAT16_MIN_RESERVED: u32 = 1;

/// Fewest reserved sectors of a FAT32 volume: the count the specification recommends, which
/// holds the boot sector, the `FSInfo` sector, and their backups.
const FAT32_MIN_RESERVED: u32 = 32;

/// The FAT32 `FSInfo` sector.
const FSINFO_SECTOR: u16 = 1;

/// The FAT32 backup boot sector; the backup `FSInfo` sector follows it.
const BACKUP_BOOT_SECTOR: u16 = 6;

/// The first data cluster, which holds a FAT32 volume's root directory.
const FIRST_CLUSTER: u32 = 2;

/// Fewest clusters of a FAT32 volume: the type rule makes a volume with fewer FAT16.
const FAT32_MIN_CLUSTERS: u32 = 65_525;

/// Most clusters of a FAT32 volume: its cluster numbers stop below the bad-cluster marker
/// `0x0FFF_FFF7`.
const FAT32_MAX_CLUSTERS: u32 = 0x0FFF_FFF5;

/// The media descriptor of a fixed disk, which the low byte of FAT entry 0 repeats.
const MEDIA: u8 = 0xF8;

/// Bytes of a directory entry.
const ENTRY_BYTES: usize = 32;

/// Long-name characters one directory slot holds.
const LFN_SLOT_UNITS: usize = 13;

/// The attribute of a directory's short entry.
const ATTR_DIRECTORY: u8 = 0x10;

/// The attribute of a file's short entry.
const ATTR_ARCHIVE: u8 = 0x20;

/// The date of every entry, 1980-01-01, the first a FAT date holds (year 0, month 1, day 1).
const EPOCH_DATE: u16 = (1 << 5) | 1;

/// The volume label of the boot sector: the specification's value for a volume with none.
const VOLUME_LABEL: &[u8; 11] = b"NO NAME    ";

/// The boot sector's OEM name, the value the specification recommends.
const OEM_NAME: &[u8; 8] = b"MSWIN4.1";

/// Characters a long name may not hold, beside the control characters.
const LFN_FORBIDDEN: &[char] = &['"', '*', '/', ':', '<', '>', '?', '\\', '|'];

/// The FAT variant of a volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Variant
{
    Fat16,
    Fat32,
}

impl Variant
{
    /// The variant as `fatfs-parse` names it.
    fn fat_type(self) -> FatType
    {
        match self
        {
            Self::Fat16 => FatType::Fat16,
            Self::Fat32 => FatType::Fat32,
        }
    }

    /// Bytes of one FAT entry.
    fn entry_bytes(self) -> u32
    {
        match self
        {
            Self::Fat16 => 2,
            Self::Fat32 => 4,
        }
    }

    /// The FAT entry of a chain's last cluster, and of the reserved entry 1.
    fn end_of_chain(self) -> u32
    {
        match self
        {
            Self::Fat16 => 0xFFFF,
            Self::Fat32 => 0x0FFF_FFFF,
        }
    }

    /// Fewest reserved sectors.
    fn min_reserved(self) -> u32
    {
        match self
        {
            Self::Fat16 => FAT16_MIN_RESERVED,
            Self::Fat32 => FAT32_MIN_RESERVED,
        }
    }

    /// Entries of the fixed root directory area; FAT32 has none.
    fn root_entries(self) -> u16
    {
        match self
        {
            Self::Fat16 => FAT16_ROOT_ENTRIES,
            Self::Fat32 => 0,
        }
    }

    /// Whether the type rule makes a volume of `clusters` clusters this variant.
    fn holds(self, clusters: u32) -> bool
    {
        match self
        {
            Self::Fat16 => (fat_parse::FAT16_MIN_CLUSTERS..FAT32_MIN_CLUSTERS).contains(&clusters),
            Self::Fat32 => (FAT32_MIN_CLUSTERS..=FAT32_MAX_CLUSTERS).contains(&clusters),
        }
    }

    /// The file-system type label of the boot sector.
    fn label(self) -> &'static [u8; 8]
    {
        match self
        {
            Self::Fat16 => b"FAT16   ",
            Self::Fat32 => b"FAT32   ",
        }
    }

    /// The second byte of the boot sector's jump, which lands past the extended parameter
    /// block: offset 0x3E on FAT16, 0x5A on FAT32.
    fn jump(self) -> u8
    {
        match self
        {
            Self::Fat16 => 0x3C,
            Self::Fat32 => 0x58,
        }
    }
}

/// Where a volume's structures lie, in sectors from its start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Geometry
{
    variant: Variant,
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    /// Sectors of one FAT copy.
    fat_sectors: u32,
    /// Sectors of the FAT16 fixed root directory area; 0 on FAT32.
    root_sectors: u32,
    total_sectors: u32,
    /// The first sector of the data region, a multiple of `sectors_per_cluster`.
    data_start: u32,
    /// Data clusters, numbered from [`FIRST_CLUSTER`].
    clusters: u32,
}

impl Geometry
{
    /// Byte offset of `sector` from the volume's start.
    fn sector_offset(&self, sector: u32) -> u64
    {
        // A u32 by u16 product fits a u64, so this never saturates.
        u64::from(sector).saturating_mul(u64::from(self.bytes_per_sector))
    }

    /// The first sector of the FAT16 fixed root directory area, which ends where the data
    /// region starts.
    fn root_area(&self) -> u32
    {
        // [`layout`] puts the area below `data_start`, so this never saturates.
        self.data_start.saturating_sub(self.root_sectors)
    }
}

/// The geometry of a `volume_bytes`-byte volume of `bytes_per_sector`-byte sectors: FAT16
/// when that layout has a FAT16 cluster count, else FAT32 when that one has a FAT32 count.
///
/// # Errors
/// Fails when `bytes_per_sector` is not a power of two from 512 to [`CLUSTER_BYTES`], when the
/// volume has more sectors than a `u32` counts, or when neither layout's cluster count is its
/// variant's: a volume too small for FAT16, or one in the narrow range whose FAT16 layout has
/// too many clusters and whose FAT32 layout, with its larger FAT, too few.
fn geometry(volume_bytes: u64, bytes_per_sector: u16) -> Result<Geometry>
{
    let sector = u32::from(bytes_per_sector);
    let Some(sectors_per_cluster) = CLUSTER_BYTES.checked_div(sector).filter(|_| {
        fat_parse::is_sector_size(usize::from(bytes_per_sector)) && sector <= CLUSTER_BYTES
    })
    else
    {
        bail!(
            "FAT sector size {bytes_per_sector} is not a power of two from 512 to {CLUSTER_BYTES}"
        );
    };
    let total_sectors = volume_bytes
        .checked_div(u64::from(sector))
        .and_then(|sectors| u32::try_from(sectors).ok())
        .with_context(|| {
            format!("a {volume_bytes}-byte volume has more sectors than FAT counts")
        })?;
    [Variant::Fat16, Variant::Fat32]
        .into_iter()
        .filter_map(|variant| {
            layout(
                variant,
                bytes_per_sector,
                sectors_per_cluster,
                total_sectors,
            )
        })
        .find(|geo| geo.variant.holds(geo.clusters))
        .with_context(|| {
            format!(
                "a {volume_bytes}-byte volume of {bytes_per_sector}-byte sectors and \
                 {CLUSTER_BYTES}-byte clusters has a cluster count neither FAT16 ({} to {}) \
                 nor FAT32 (from {FAT32_MIN_CLUSTERS}) admits",
                fat_parse::FAT16_MIN_CLUSTERS,
                FAT32_MIN_CLUSTERS.saturating_sub(1)
            )
        })
}

/// The `variant` layout of a volume of `total_sectors` sectors: the data region starts at the
/// first cluster boundary past the variant's fewest reserved sectors, the FATs and the root
/// directory area, the reserved sectors grown to reach it, and each FAT is the smallest that
/// holds an entry for every cluster the data region then has. `None` when the volume cannot
/// hold that much, or a field overflows its on-disk width.
fn layout(
    variant: Variant,
    bytes_per_sector: u16,
    sectors_per_cluster: u32,
    total_sectors: u32,
) -> Option<Geometry>
{
    let sector = u32::from(bytes_per_sector);
    let root_bytes =
        u32::from(variant.root_entries()).checked_mul(u32::try_from(ENTRY_BYTES).ok()?)?;
    let root_sectors = root_bytes.div_ceil(sector);
    let mut fat_sectors = 1u32;
    loop
    {
        let fats = FAT_COUNT.checked_mul(fat_sectors)?;
        let data_start = variant
            .min_reserved()
            .checked_add(fats)?
            .checked_add(root_sectors)?
            .checked_next_multiple_of(sectors_per_cluster)?;
        let clusters = total_sectors
            .checked_sub(data_start)?
            .checked_div(sectors_per_cluster)?;
        // The FAT holds the two reserved entries and one per cluster.
        let needed = u64::from(clusters)
            .checked_add(2)?
            .checked_mul(u64::from(variant.entry_bytes()))?
            .div_ceil(u64::from(sector));
        let needed = u32::try_from(needed).ok()?;
        if needed <= fat_sectors
        {
            let reserved = data_start.checked_sub(fats)?.checked_sub(root_sectors)?;
            return Some(Geometry {
                variant,
                bytes_per_sector,
                sectors_per_cluster: u8::try_from(sectors_per_cluster).ok()?,
                reserved_sectors: u16::try_from(reserved).ok()?,
                fat_sectors,
                root_sectors,
                total_sectors,
                data_start,
                clusters,
            });
        }
        // A larger FAT leaves no more clusters, so the next pass needs no larger a FAT and
        // the loop ends there.
        fat_sectors = needed;
    }
}

/// A file or directory of the tree a volume holds.
pub struct Entry
{
    /// The name in its directory.
    pub name: String,
    /// What the entry is.
    pub kind: Kind,
}

/// What an [`Entry`] is.
pub enum Kind
{
    /// A file whose `len` bytes are read from the host file at `path`.
    File
    {
        path: PathBuf, len: u64
    },
    /// A directory and its entries, written in this order.
    Dir(Vec<Entry>),
}

/// Write a FAT volume holding `root` to the `volume_bytes` bytes of `image` from byte
/// `offset`: sectors of `bytes_per_sector` bytes, laid out as [`geometry`] says, and the
/// volume serial number `volume_id`.
///
/// The volume's bytes must be zero, as those of a new image are: the writer writes only the
/// sectors that hold something.
///
/// # Errors
/// Fails as [`geometry`] does; when a name cannot be stored ([`short_names`]); when the tree
/// does not fit the volume, or its root does not fit a FAT16 root directory area; when a file
/// exceeds a FAT file's `u32` size or does not hold the bytes its entry gives; and on an I/O
/// error.
pub fn write_volume<W: Write + Seek>(
    image: &mut W,
    offset: u64,
    volume_bytes: u64,
    bytes_per_sector: u16,
    volume_id: u32,
    root: &[Entry],
) -> Result<()>
{
    let geo = geometry(volume_bytes, bytes_per_sector)?;
    let mut writer = Writer {
        geo,
        fat: empty_fat(&geo)?,
        next: FIRST_CLUSTER,
        image,
        offset,
        volume_bytes,
    };
    match geo.variant
    {
        Variant::Fat16 => writer.fixed_root(root)?,
        Variant::Fat32 =>
        {
            writer.directory(root, None)?;
        }
    }
    writer.finish(volume_id)
}

/// A FAT copy of `geo` whose only entries in use are the two reserved ones.
fn empty_fat(geo: &Geometry) -> Result<Vec<u8>>
{
    let bytes =
        usize::try_from(geo.sector_offset(geo.fat_sectors)).context("FAT exceeds memory")?;
    let mut fat = vec![0u8; bytes];
    let fat_type = geo.variant.fat_type();
    // Entry 0 repeats the media descriptor in its low byte, all its other bits set; entry 1
    // is an end-of-chain value, whose top bits also mark the volume clean.
    let entry0 = 0x0FFF_FF00 | u32::from(MEDIA);
    fat_parse::write_fat_entry(&mut fat, fat_type, 0, entry0).context("FAT holds no entry 0")?;
    let entry1 = usize::try_from(geo.variant.entry_bytes()).context("FAT entry size")?;
    fat_parse::write_fat_entry(&mut fat, fat_type, entry1, geo.variant.end_of_chain())
        .context("FAT holds no entry 1")?;
    Ok(fat)
}

/// The state of one volume's write: its geometry, its FAT as it grows, and where it lies in
/// the image.
struct Writer<'a, W>
{
    geo: Geometry,
    fat: Vec<u8>,
    /// The next cluster to allocate; every cluster before it is in use.
    next: u32,
    image: &'a mut W,
    /// Byte offset of the volume in `image`.
    offset: u64,
    volume_bytes: u64,
}

impl<W: Write + Seek> Writer<'_, W>
{
    /// Allocate `count` contiguous clusters as one chain; returns the first.
    fn alloc(&mut self, count: u32) -> Result<u32>
    {
        let first = self.next;
        let clusters = self.geo.clusters;
        let end = first
            .checked_add(count)
            .filter(|&end| end.checked_sub(FIRST_CLUSTER).is_some_and(|used| used <= clusters))
            .with_context(|| {
                format!("the tree does not fit the volume's {clusters} clusters of {CLUSTER_BYTES} bytes")
            })?;
        let fat_type = self.geo.variant.fat_type();
        for cluster in first..end
        {
            let link = cluster.saturating_add(1);
            let value = if link == end
            {
                self.geo.variant.end_of_chain()
            }
            else
            {
                link
            };
            let at = cluster
                .checked_mul(self.geo.variant.entry_bytes())
                .and_then(|at| usize::try_from(at).ok())
                .context("FAT entry offset overflows")?;
            fat_parse::write_fat_entry(&mut self.fat, fat_type, at, value)
                .with_context(|| format!("cluster {cluster} has no entry in the FAT"))?;
        }
        self.next = end;
        Ok(first)
    }

    /// Byte offset of `cluster` from the volume's start.
    fn cluster_offset(&self, cluster: u32) -> Result<u64>
    {
        let sector = cluster
            .checked_sub(FIRST_CLUSTER)
            .and_then(|index| index.checked_mul(u32::from(self.geo.sectors_per_cluster)))
            .and_then(|sectors| sectors.checked_add(self.geo.data_start))
            .with_context(|| format!("cluster {cluster} lies outside the data region"))?;
        Ok(self.geo.sector_offset(sector))
    }

    /// Seek to byte `at` of the volume, refusing `len` bytes from there that would pass its
    /// end.
    fn seek(&mut self, at: u64, len: u64) -> Result<()>
    {
        ensure!(
            at.checked_add(len)
                .is_some_and(|end| end <= self.volume_bytes),
            "a {len}-byte write at byte {at} passes the volume's end"
        );
        let abs = self
            .offset
            .checked_add(at)
            .context("volume offset exceeds u64")?;
        self.image
            .seek(SeekFrom::Start(abs))
            .context("failed to seek in the image")?;
        Ok(())
    }

    /// Write `bytes` at byte `at` of the volume.
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> Result<()>
    {
        self.seek(at, u64::try_from(bytes.len()).context("write exceeds u64")?)?;
        self.image
            .write_all(bytes)
            .context("failed to write the image")
    }

    /// Allocate a file's clusters and copy its `len` bytes from `path` into them; returns its
    /// first cluster, 0 for an empty file.
    fn file(&mut self, path: &Path, len: u64) -> Result<u32>
    {
        ensure!(
            u32::try_from(len).is_ok(),
            "{} has {len} bytes, more than a FAT file holds",
            path.display()
        );
        if len == 0
        {
            return Ok(0);
        }
        let clusters =
            u32::try_from(len.div_ceil(u64::from(CLUSTER_BYTES))).context("cluster count")?;
        let first = self.alloc(clusters)?;
        let at = self.cluster_offset(first)?;
        self.seek(at, len)?;
        let source =
            File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
        let copied = io::copy(&mut source.take(len), &mut *self.image)
            .with_context(|| format!("failed to copy {} into the image", path.display()))?;
        ensure!(
            copied == len,
            "{} holds {copied} bytes, not the {len} it had",
            path.display()
        );
        Ok(first)
    }

    /// Write a clustered directory holding `entries`, and everything under it; returns its
    /// first cluster. `parent` is the cluster its `..` entry names (0 for the root), or
    /// `None` for a FAT32 root directory, which has no `.` and `..` entries.
    fn directory(&mut self, entries: &[Entry], parent: Option<u32>) -> Result<u32>
    {
        let names = short_names(entries)?;
        let dots = if parent.is_some() { 2 } else { 0 };
        let slots = names
            .iter()
            .map(Name::slots)
            .try_fold(dots, usize::checked_add)
            .context("slot count")?;
        let bytes = slots.checked_mul(ENTRY_BYTES).context("directory size")?;
        let cluster = usize::try_from(CLUSTER_BYTES).context("cluster size")?;
        let clusters = bytes.div_ceil(cluster).max(1);
        let first = self.alloc(u32::try_from(clusters).context("directory cluster count")?)?;
        let mut dir = Vec::with_capacity(clusters.saturating_mul(cluster));
        // Its subdirectories' `..` entries name this directory, or 0 for the root.
        let this = match parent
        {
            Some(parent) =>
            {
                dir.extend_from_slice(&short_entry(b".          ", ATTR_DIRECTORY, first, 0));
                dir.extend_from_slice(&short_entry(b"..         ", ATTR_DIRECTORY, parent, 0));
                first
            }
            None => 0,
        };
        self.entries(entries, &names, this, &mut dir)?;
        dir.resize(clusters.saturating_mul(cluster), 0);
        let at = self.cluster_offset(first)?;
        self.write_at(at, &dir)?;
        Ok(first)
    }

    /// Write the FAT16 fixed root directory holding `entries`, and everything under it.
    fn fixed_root(&mut self, entries: &[Entry]) -> Result<()>
    {
        let names = short_names(entries)?;
        let capacity = usize::from(self.geo.variant.root_entries());
        let slots = names
            .iter()
            .map(Name::slots)
            .try_fold(0usize, usize::checked_add)
            .context("slot count")?;
        ensure!(
            slots <= capacity,
            "the root directory's {slots} entries exceed the {capacity} of a FAT16 root"
        );
        let mut dir = Vec::with_capacity(capacity.saturating_mul(ENTRY_BYTES));
        self.entries(entries, &names, 0, &mut dir)?;
        let at = self.geo.sector_offset(self.geo.root_area());
        self.write_at(at, &dir)
    }

    /// Write everything under `entries`, then append their directory entries to `dir`: each
    /// one's long-name slots, then its short entry. `this` is the cluster of the directory
    /// that holds them, which a subdirectory's `..` entry names.
    fn entries(
        &mut self,
        entries: &[Entry],
        names: &[Name],
        this: u32,
        dir: &mut Vec<u8>,
    ) -> Result<()>
    {
        for (entry, name) in entries.iter().zip(names)
        {
            let (attr, cluster, size) = match &entry.kind
            {
                Kind::Dir(children) => (ATTR_DIRECTORY, self.directory(children, Some(this))?, 0),
                Kind::File { path, len } =>
                {
                    let cluster = self.file(path, *len)?;
                    (
                        ATTR_ARCHIVE,
                        cluster,
                        u32::try_from(*len).context("file size")?,
                    )
                }
            };
            name.encode(dir, attr, cluster, size)?;
        }
        Ok(())
    }

    /// Write the boot sector, on FAT32 its `FSInfo` sector and both backups, and every FAT
    /// copy.
    fn finish(mut self, volume_id: u32) -> Result<()>
    {
        let geo = self.geo;
        let boot = boot_sector(&geo, volume_id)?;
        self.write_at(0, &boot)?;
        if geo.variant == Variant::Fat32
        {
            // Every cluster before `next` is in use and none after it.
            let used = self.next.saturating_sub(FIRST_CLUSTER);
            let free = geo.clusters.saturating_sub(used);
            let next_free = if free == 0 { u32::MAX } else { self.next };
            let info = fsinfo_sector(&geo, free, next_free);
            self.write_at(geo.sector_offset(u32::from(FSINFO_SECTOR)), &info)?;
            self.write_at(geo.sector_offset(u32::from(BACKUP_BOOT_SECTOR)), &boot)?;
            let backup_info = BACKUP_BOOT_SECTOR.saturating_add(FSINFO_SECTOR);
            self.write_at(geo.sector_offset(u32::from(backup_info)), &info)?;
        }
        let fat = std::mem::take(&mut self.fat);
        let mut sector = u32::from(geo.reserved_sectors);
        for _ in 0..FAT_COUNT
        {
            self.write_at(geo.sector_offset(sector), &fat)?;
            sector = sector
                .checked_add(geo.fat_sectors)
                .context("FAT sector overflows")?;
        }
        Ok(())
    }
}

/// The boot sector of a volume of `geo` with the serial number `volume_id`: a jump over the
/// parameter block, the BIOS parameter block and its FAT16 or FAT32 extension, no boot code,
/// and the boot signature at bytes 510 and 511.
fn boot_sector(geo: &Geometry, volume_id: u32) -> Result<Vec<u8>>
{
    let sector = usize::from(geo.bytes_per_sector);
    let mut b = Vec::with_capacity(sector);
    b.extend_from_slice(&[0xEB, geo.variant.jump(), 0x90]);
    b.extend_from_slice(OEM_NAME);
    b.extend_from_slice(&geo.bytes_per_sector.to_le_bytes());
    b.push(geo.sectors_per_cluster);
    b.extend_from_slice(&geo.reserved_sectors.to_le_bytes());
    b.push(u8::try_from(FAT_COUNT).context("FAT count")?);
    b.extend_from_slice(&geo.variant.root_entries().to_le_bytes());
    // A FAT16 volume whose sector count fits the 16-bit field gives it there; any other
    // gives it in the 32-bit field.
    let total16 = match geo.variant
    {
        Variant::Fat16 => u16::try_from(geo.total_sectors).unwrap_or(0),
        Variant::Fat32 => 0,
    };
    let total32 = if total16 == 0 { geo.total_sectors } else { 0 };
    b.extend_from_slice(&total16.to_le_bytes());
    b.push(MEDIA);
    let fat16_sectors = match geo.variant
    {
        Variant::Fat16 =>
        {
            u16::try_from(geo.fat_sectors).context("FAT16 FAT exceeds 65535 sectors")?
        }
        Variant::Fat32 => 0,
    };
    b.extend_from_slice(&fat16_sectors.to_le_bytes());
    // Sectors per track and heads, for a BIOS geometry no reader here uses; no hidden
    // sectors.
    b.extend_from_slice(&63u16.to_le_bytes());
    b.extend_from_slice(&255u16.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&total32.to_le_bytes());
    if geo.variant == Variant::Fat32
    {
        b.extend_from_slice(&geo.fat_sectors.to_le_bytes());
        // Every FAT copy mirrored, file-system version 0.0.
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&FIRST_CLUSTER.to_le_bytes());
        b.extend_from_slice(&FSINFO_SECTOR.to_le_bytes());
        b.extend_from_slice(&BACKUP_BOOT_SECTOR.to_le_bytes());
        b.extend_from_slice(&[0u8; 12]);
    }
    // Drive number 0x80 (a fixed disk), a reserved byte, and the extended boot signature,
    // which says the serial number and the two labels follow.
    b.extend_from_slice(&[0x80, 0x00, 0x29]);
    b.extend_from_slice(&volume_id.to_le_bytes());
    b.extend_from_slice(VOLUME_LABEL);
    b.extend_from_slice(geo.variant.label());
    b.resize(510, 0);
    b.extend_from_slice(&[0x55, 0xAA]);
    b.resize(sector, 0);
    Ok(b)
}

/// The FAT32 `FSInfo` sector of `geo`: its signatures, the free cluster count `free`, and the
/// next free cluster `next_free` (`u32::MAX` for none).
fn fsinfo_sector(geo: &Geometry, free: u32, next_free: u32) -> Vec<u8>
{
    let sector = usize::from(geo.bytes_per_sector);
    let mut s = Vec::with_capacity(sector);
    s.extend_from_slice(&0x4161_5252u32.to_le_bytes());
    s.resize(484, 0);
    s.extend_from_slice(&0x6141_7272u32.to_le_bytes());
    s.extend_from_slice(&free.to_le_bytes());
    s.extend_from_slice(&next_free.to_le_bytes());
    s.resize(508, 0);
    s.extend_from_slice(&0xAA55_0000u32.to_le_bytes());
    s.resize(sector, 0);
    s
}

/// A short entry: the 8.3 name `name`, `attr`, the first cluster `cluster`, the size `size`,
/// and every timestamp 1980-01-01 00:00:00.
fn short_entry(name: &[u8; 11], attr: u8, cluster: u32, size: u32) -> [u8; ENTRY_BYTES]
{
    let [lo0, lo1, hi0, hi1] = cluster.to_le_bytes();
    let date = EPOCH_DATE.to_le_bytes();
    let mut e = [0u8; ENTRY_BYTES];
    e[..11].copy_from_slice(name);
    e[11] = attr;
    // Byte 12 (no case flags), the creation time's tenths (13) and the creation time (14 and
    // 15) stay zero: 00:00:00.
    e[16..18].copy_from_slice(&date);
    e[18..20].copy_from_slice(&date);
    e[20..22].copy_from_slice(&[hi0, hi1]);
    // The write time (22 and 23) stays zero.
    e[24..26].copy_from_slice(&date);
    e[26..28].copy_from_slice(&[lo0, lo1]);
    e[28..32].copy_from_slice(&size.to_le_bytes());
    e
}

/// The names an entry is stored under: its short name, and the UTF-16 code units of its long
/// name when it has one.
#[derive(Debug, PartialEq, Eq)]
struct Name
{
    short: [u8; 11],
    long: Option<Vec<u16>>,
}

impl Name
{
    /// The directory slots the entry takes: its long-name slots and its short entry.
    fn slots(&self) -> usize
    {
        let long = self
            .long
            .as_ref()
            .map_or(0, |units| units.len().div_ceil(LFN_SLOT_UNITS));
        long.saturating_add(1)
    }

    /// Append the entry's slots to `dir`: its long-name slots, last first, then its short
    /// entry with `attr`, `cluster` and `size`.
    fn encode(&self, dir: &mut Vec<u8>, attr: u8, cluster: u32, size: u32) -> Result<()>
    {
        if let Some(units) = &self.long
        {
            let checksum = fat_parse::lfn_checksum(&self.short);
            let count = units.len().div_ceil(LFN_SLOT_UNITS);
            for seq in (1..=count).rev()
            {
                let slot = u8::try_from(seq)
                    .ok()
                    .and_then(|seq_byte| {
                        fat_parse::pack_lfn_slot(seq_byte, seq == count, checksum, units)
                    })
                    .context("long name exceeds 255 characters")?;
                dir.extend_from_slice(&slot);
            }
        }
        dir.extend_from_slice(&short_entry(&self.short, attr, cluster, size));
        Ok(())
    }
}

/// The names each of `entries`, one directory's, is stored under, in order. A name that
/// [`exact_short_name`] gives a short name is stored as that alone. Any other takes a long
/// name and a short name from its [`basis_name`]: the basis itself when it renders the name
/// with its case alone changed and is free, else the basis with the lowest numeric tail that
/// is free. A short name is free when no other entry has it and no other entry's name is
/// looked up as it: the `fatfs` service's lookup returns the first entry whose long name or
/// short name matches (`fat_parse::name_matches`), so such a short name, earlier in the
/// directory, would open the wrong entry.
///
/// # Errors
/// Fails when a name is empty, longer than 255 UTF-16 code units, holds a control character
/// or one of [`LFN_FORBIDDEN`], ends in a space or a period, equals another of the
/// directory's names but for case, or is an 8.3 name another of the directory's names is
/// looked up as, which FAT's case-insensitive lookup could not tell apart.
fn short_names(entries: &[Entry]) -> Result<Vec<Name>>
{
    let mut folded = HashSet::new();
    for entry in entries
    {
        check_long_name(&entry.name)?;
        ensure!(
            folded.insert(entry.name.to_lowercase()),
            "{:?} differs from another name of its directory only in case",
            entry.name
        );
    }
    let exact: Vec<Option<[u8; 11]>> = entries.iter().map(|e| exact_short_name(&e.name)).collect();
    let mut taken: HashSet<[u8; 11]> = exact.iter().flatten().copied().collect();
    // The other entry whose name the entry at `own` would shadow with `short`.
    let shadowed = |short: &[u8; 11], own: usize| {
        entries
            .iter()
            .enumerate()
            .find(|&(at, other)| at != own && fat_parse::name_matches(short, other.name.as_bytes()))
            .map(|(_, other)| other.name.as_str())
    };
    let mut names = Vec::with_capacity(entries.len());
    for (own, (entry, exact)) in entries.iter().zip(exact).enumerate()
    {
        if let Some(short) = exact
        {
            if let Some(other) = shadowed(&short, own)
            {
                bail!(
                    "{:?} is the short name {other:?}, of the same directory, is looked up as",
                    entry.name
                );
            }
            names.push(Name { short, long: None });
            continue;
        }
        let free = |name: &[u8; 11]| !taken.contains(name) && shadowed(name, own).is_none();
        let (basis, lossy) = basis_name(&entry.name);
        let short = if !lossy && free(&basis)
        {
            basis
        }
        else
        {
            (1..=fat_parse::MAX_NUMERIC_TAIL)
                .filter_map(|tail| fat_parse::compose_tailed_name(&basis, tail))
                .find(|name| free(name))
                .with_context(|| format!("no numeric tail is free for {:?}", entry.name))?
        };
        taken.insert(short);
        names.push(Name {
            short,
            long: Some(entry.name.encode_utf16().collect()),
        });
    }
    Ok(names)
}

/// Refuse a name no FAT long name can be: see [`short_names`].
fn check_long_name(name: &str) -> Result<()>
{
    ensure!(!name.is_empty(), "a directory entry has an empty name");
    ensure!(
        name.encode_utf16().count() <= fat_parse::MAX_LFN_CHARS,
        "{name:?} exceeds the {} UTF-16 code units of a FAT long name",
        fat_parse::MAX_LFN_CHARS
    );
    ensure!(
        !name
            .chars()
            .any(|c| c.is_control() || LFN_FORBIDDEN.contains(&c)),
        "{name:?} holds a character a FAT name cannot"
    );
    ensure!(
        !name.ends_with([' ', '.']),
        "{name:?} ends in a space or a period, which FAT names drop"
    );
    Ok(())
}

/// Whether `b` may appear in a short name: an upper-case letter, a digit, or one of the
/// specification's punctuation characters.
fn is_short_char(b: u8) -> bool
{
    matches!(
        b,
        b'A'..=b'Z'
            | b'0'..=b'9'
            | b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'-'
            | b'@'
            | b'^'
            | b'_'
            | b'`'
            | b'{'
            | b'}'
            | b'~'
    )
}

/// The short name of `name` when it is an 8.3 name as it stands: one to eight short-name
/// characters, then, after one period, one to three more; `None` otherwise.
fn exact_short_name(name: &str) -> Option<[u8; 11]>
{
    let (base, ext) = name.split_once('.').unwrap_or((name, ""));
    let fits = (1..=8).contains(&base.len())
        && ext.len() <= 3
        && ext.is_empty() != name.contains('.')
        && base.bytes().chain(ext.bytes()).all(is_short_char);
    fits.then(|| pad_short(base.bytes(), ext.bytes()))
}

/// The basis of `name`'s short name, and whether it renders the name with more than its
/// case changed: the characters before the name's first period, past any leading ones, and
/// up to three after its last period, upper-cased, with spaces dropped and any other
/// character a short name cannot hold as `_`; the base at most eight characters, and `_`
/// when nothing is left of it.
fn basis_name(name: &str) -> ([u8; 11], bool)
{
    let trimmed = name.trim_start_matches('.');
    let mut lossy = trimmed.len() != name.len() || trimmed.matches('.').count() > 1;
    let (base, ext) = match trimmed.rsplit_once('.')
    {
        Some((base, ext)) => (base.split('.').next().unwrap_or_default(), ext),
        None => (trimmed, ""),
    };
    let mut convert = |part: &str, keep: usize| {
        let mut out = Vec::with_capacity(keep);
        for c in part.chars()
        {
            if c == ' '
            {
                lossy = true;
                continue;
            }
            let b = u8::try_from(c.to_ascii_uppercase())
                .ok()
                .filter(|&b| is_short_char(b));
            lossy |= b.is_none() || out.len() == keep;
            if out.len() < keep
            {
                out.push(b.unwrap_or(b'_'));
            }
        }
        out
    };
    let mut base = convert(base, 8);
    let ext = convert(ext, 3);
    if base.is_empty()
    {
        base.push(b'_');
        lossy = true;
    }
    (pad_short(base.into_iter(), ext.into_iter()), lossy)
}

/// The 11-byte short name of `base` and `ext`, space-padded to 8 and 3 bytes.
fn pad_short(base: impl Iterator<Item = u8>, ext: impl Iterator<Item = u8>) -> [u8; 11]
{
    let mut out = [b' '; 11];
    for (dst, b) in out[..8].iter_mut().zip(base)
    {
        *dst = b;
    }
    for (dst, b) in out[8..].iter_mut().zip(ext)
    {
        *dst = b;
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::Cursor;

    use super::*;
    use crate::fat_read::{Node, read_volume};

    const MIB: u64 = 1024 * 1024;

    /// A scratch directory unique to this process and `name`, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch
    {
        fn new(name: &str) -> Self
        {
            let dir =
                std::env::temp_dir().join(format!("seraph-fat-{}-{name}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        /// A host file named `name` holding `bytes`, as an entry.
        fn file(&self, name: &str, bytes: &[u8]) -> Entry
        {
            let path = self
                .0
                .join(format!("f{}", fs::read_dir(&self.0).unwrap().count()));
            fs::write(&path, bytes).unwrap();
            Entry {
                name: name.to_owned(),
                kind: Kind::File {
                    path,
                    len: bytes.len() as u64,
                },
            }
        }
    }

    impl Drop for Scratch
    {
        fn drop(&mut self)
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn dir(name: &str, entries: Vec<Entry>) -> Entry
    {
        Entry {
            name: name.to_owned(),
            kind: Kind::Dir(entries),
        }
    }

    /// A zero image file of `bytes` bytes in `scratch`, sparse on the host.
    fn image(scratch: &Scratch, bytes: u64) -> File
    {
        let path = scratch.0.join("volume.img");
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .unwrap();
        file.set_len(bytes).unwrap();
        file
    }

    #[test]
    fn the_authored_sizes_are_fat16_and_a_larger_volume_fat32()
    {
        for sector in [512u16, 4096]
        {
            for (mib, variant) in [
                (64, Variant::Fat16),
                (192, Variant::Fat16),
                (256, Variant::Fat16),
                (512, Variant::Fat32),
            ]
            {
                let geo = geometry(mib * MIB, sector).unwrap();
                assert_eq!(geo.variant, variant, "{mib} MiB, {sector}-byte sectors");
                assert_eq!(geo.data_start % u32::from(geo.sectors_per_cluster), 0);
                assert_eq!(
                    u32::from(geo.sectors_per_cluster) * u32::from(sector),
                    CLUSTER_BYTES
                );
            }
        }
    }

    // The specification's FAT32 layout (32 reserved sectors) of this size has fewer than
    // 65525 clusters and its FAT16 layout more than 65524.
    #[test]
    fn a_size_neither_variant_admits_is_refused()
    {
        let fat16 = layout(Variant::Fat16, 512, 8, 524_800).unwrap();
        let fat32 = layout(Variant::Fat32, 512, 8, 524_800).unwrap();
        assert!(!Variant::Fat16.holds(fat16.clusters) && !Variant::Fat32.holds(fat32.clusters));
        geometry(524_800 * 512, 512).unwrap_err();
        geometry(15 * MIB, 512).unwrap_err();
        geometry(64 * MIB, 1024 * 8).unwrap_err();
        geometry(64 * MIB, 768).unwrap_err();
    }

    // The boot sector the writer emits decodes, through the fatfs service's own parser, to
    // the geometry it was laid out from.
    #[test]
    fn the_boot_sector_decodes_to_its_geometry()
    {
        for sector in [512u16, 4096]
        {
            for mib in [17, 64, 256, 300]
            {
                let geo = geometry(mib * MIB, sector).unwrap();
                let Ok(bpb) = fat_parse::parse_bpb_geometry(
                    &boot_sector(&geo, 7).unwrap(),
                    u32::from(sector),
                )
                else
                {
                    panic!("{mib} MiB: the boot sector does not decode");
                };
                assert_eq!(bpb.data_start_sector, geo.data_start, "{mib} MiB");
                assert_eq!(bpb.total_clusters, geo.clusters, "{mib} MiB");
                assert_eq!(bpb.reserved_sectors, geo.reserved_sectors);
                assert_eq!(bpb.fat_size, geo.fat_sectors);
                assert_eq!(
                    matches!(bpb.fat_type, FatType::Fat32),
                    geo.variant == Variant::Fat32
                );
            }
        }
    }

    fn names(list: &[&str]) -> Result<Vec<Name>>
    {
        let entries: Vec<Entry> = list.iter().map(|n| dir(n, Vec::new())).collect();
        short_names(&entries)
    }

    fn short(name: &Name) -> &str
    {
        std::str::from_utf8(&name.short).unwrap()
    }

    #[test]
    fn short_names_keep_an_exact_name_and_give_any_other_a_long_name()
    {
        let got = names(&[
            "INIT",
            "README.TXT",
            "init.d",
            "Mixed.Rs",
            "a.b.c",
            ".hidden",
            "long file name.json",
            "long file other.json",
            "LONGFI~1.JSO",
        ])
        .unwrap();
        let shorts: Vec<&str> = got.iter().map(short).collect();
        assert_eq!(
            shorts,
            [
                "INIT       ",
                "README  TXT",
                "INIT    D  ",
                "MIXED   RS ",
                "A~1     C  ",
                "HIDDEN~1   ",
                "LONGFI~2JSO",
                "LONGFI~3JSO",
                "LONGFI~1JSO"
            ]
        );
        assert!(got[0].long.is_none() && got[1].long.is_none() && got[8].long.is_none());
        assert!(got[2..8].iter().all(|n| n.long.is_some()));
    }

    #[test]
    fn short_names_refuse_what_no_fat_name_can_be()
    {
        for bad in ["", "a:b", "tab\there", "dot.", "space ", &"x".repeat(256)]
        {
            names(&[bad]).unwrap_err();
        }
        names(&["Same", "sAME"]).unwrap_err();
        names(&[&"x".repeat(255)]).unwrap();
    }

    /// Defect caught: a short name that equals the name another entry of the directory is
    /// looked up as, which `fatfs`'s first-match lookup resolves to the wrong entry when it
    /// comes first: a generated tail taken from under a later sibling's name, or an exact
    /// 8.3 name a sibling's name is looked up as.
    #[test]
    fn no_short_name_is_one_another_entry_is_looked_up_as()
    {
        let list = [
            "Foo Bar",
            "foobar~1",
            "Bar Baz.txt",
            "BARBAZ~1.TXT",
            "barbaz~2.txt",
        ];
        let got = names(&list).unwrap();
        for (own, name) in got.iter().enumerate()
        {
            for (at, other) in list.iter().enumerate()
            {
                assert!(
                    at == own || !fat_parse::name_matches(&name.short, other.as_bytes()),
                    "{:?}'s short name {:?} is how {other:?} is looked up",
                    list[own],
                    short(name)
                );
            }
        }
        assert_eq!(short(&got[1]), "FOOBAR~1   ");
        names(&["FOOBAR~1", "foobar~1 extra"]).unwrap_err();
    }

    /// A tree that exercises every path of the writer: nested directories, an empty file, a
    /// file of several clusters, a file ending on a cluster boundary, long names, and a
    /// directory of more than one cluster.
    fn tree(scratch: &Scratch) -> (Vec<Entry>, BTreeMap<String, Node>)
    {
        let big: Vec<u8> = (0..3 * CLUSTER_BYTES + 5)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let exact = vec![0xA5u8; CLUSTER_BYTES as usize];
        let many: Vec<Entry> = (0..150)
            .map(|i| scratch.file(&format!("entry number {i}.txt"), format!("{i}").as_bytes()))
            .collect();
        let root = vec![
            scratch.file("EMPTY", b""),
            scratch.file("big.bin", &big),
            dir(
                "sub",
                vec![
                    scratch.file("EXACT.BIN", &exact),
                    dir("deeper", vec![scratch.file("leaf", b"leaf")]),
                    dir("many", many),
                ],
            ),
            scratch.file("\u{e9}t\u{e9} \u{1F600}.txt", b"unicode"),
        ];
        let mut want = BTreeMap::new();
        want.insert("/EMPTY".to_owned(), Node::File(Vec::new()));
        want.insert("/big.bin".to_owned(), Node::File(big));
        want.insert("/sub".to_owned(), Node::Dir);
        want.insert("/sub/EXACT.BIN".to_owned(), Node::File(exact));
        want.insert("/sub/deeper".to_owned(), Node::Dir);
        want.insert("/sub/deeper/leaf".to_owned(), Node::File(b"leaf".to_vec()));
        want.insert("/sub/many".to_owned(), Node::Dir);
        for i in 0..150
        {
            want.insert(
                format!("/sub/many/entry number {i}.txt"),
                Node::File(format!("{i}").into_bytes()),
            );
        }
        want.insert(
            "/\u{e9}t\u{e9} \u{1F600}.txt".to_owned(),
            Node::File(b"unicode".to_vec()),
        );
        (root, want)
    }

    #[test]
    fn a_volume_reads_back_as_the_tree_written_at_each_variant_and_sector_size()
    {
        for sector in [512u16, 4096]
        {
            for (mib, variant) in [(64, FatType::Fat16), (300, FatType::Fat32)]
            {
                let scratch = Scratch::new(&format!("round-{sector}-{mib}"));
                let (root, want) = tree(&scratch);
                let offset = 3 * u64::from(sector);
                let mut img = image(&scratch, offset + mib * MIB + 4096);
                write_volume(&mut img, offset, mib * MIB, sector, 0x1234_5678, &root).unwrap();
                assert_eq!(
                    read_volume(&mut img, offset, u32::from(sector)).unwrap(),
                    want,
                    "{mib} MiB, {sector}"
                );
                // Nothing is written outside the volume.
                let mut head = vec![0u8; usize::try_from(offset).unwrap()];
                img.seek(SeekFrom::Start(0)).unwrap();
                img.read_exact(&mut head).unwrap();
                assert!(head.iter().all(|&b| b == 0));
                let mut tail = vec![0u8; 4096];
                img.seek(SeekFrom::Start(offset + mib * MIB)).unwrap();
                img.read_exact(&mut tail).unwrap();
                assert!(tail.iter().all(|&b| b == 0));
                let geo = geometry(mib * MIB, sector).unwrap();
                assert_eq!(
                    matches!(variant, FatType::Fat32),
                    geo.variant == Variant::Fat32
                );
            }
        }
    }

    #[test]
    fn a_fat32_fsinfo_sector_counts_the_free_clusters()
    {
        let scratch = Scratch::new("fsinfo");
        let (root, _) = tree(&scratch);
        let mut img = Cursor::new(vec![0u8; usize::try_from(300 * MIB).unwrap()]);
        write_volume(&mut img, 0, 300 * MIB, 512, 1, &root).unwrap();
        let bytes = img.into_inner();
        let info = &bytes[512..1024];
        assert_eq!(&info[..4], b"RRaA");
        assert_eq!(&info[484..488], b"rrAa");
        let geo = geometry(300 * MIB, 512).unwrap();
        // Root (1), big.bin (4), sub (1), EXACT.BIN (1), deeper (1), leaf (1), many (4: two
        // dot entries and 150 of three slots, 14464 bytes), 150 one-cluster files, and the
        // unicode file (1).
        let used = 1 + 4 + 1 + 1 + 1 + 1 + 4 + 150 + 1;
        assert_eq!(
            u32::from_le_bytes(info[488..492].try_into().unwrap()),
            geo.clusters - used
        );
        assert_eq!(
            u32::from_le_bytes(info[492..496].try_into().unwrap()),
            FIRST_CLUSTER + used
        );
        // The backups are at sectors 6 and 7.
        assert_eq!(bytes[..512], bytes[6 * 512..7 * 512]);
        assert_eq!(bytes[512..1024], bytes[7 * 512..8 * 512]);
    }

    #[test]
    fn two_writes_of_a_tree_are_byte_identical()
    {
        let scratch = Scratch::new("again");
        let (root, _) = tree(&scratch);
        let write = || {
            let mut img = Cursor::new(vec![0u8; usize::try_from(64 * MIB).unwrap()]);
            write_volume(&mut img, 0, 64 * MIB, 512, 9, &root).unwrap();
            img.into_inner()
        };
        assert!(write() == write());
    }

    #[test]
    fn a_tree_the_volume_cannot_hold_is_refused()
    {
        let scratch = Scratch::new("full");
        // The fixed root of a FAT16 volume holds 512 entries.
        let root: Vec<Entry> = (0..513)
            .map(|i| dir(&format!("D{i}"), Vec::new()))
            .collect();
        let mut img = Cursor::new(vec![0u8; usize::try_from(17 * MIB).unwrap()]);
        write_volume(&mut img, 0, 17 * MIB, 512, 0, &root).unwrap_err();
        let root: Vec<Entry> = (0..512)
            .map(|i| dir(&format!("D{i}"), Vec::new()))
            .collect();
        write_volume(&mut img, 0, 17 * MIB, 512, 0, &root).unwrap();
        // More data than the volume's clusters hold.
        let path = scratch.0.join("large");
        File::create(&path).unwrap().set_len(17 * MIB).unwrap();
        let root = vec![Entry {
            name: "LARGE".to_owned(),
            kind: Kind::File {
                path,
                len: 17 * MIB,
            },
        }];
        write_volume(&mut img, 0, 17 * MIB, 512, 0, &root).unwrap_err();
        // A file shorter than its entry says.
        let path = scratch.0.join("short");
        fs::write(&path, b"abc").unwrap();
        let root = vec![Entry {
            name: "SHORT".to_owned(),
            kind: Kind::File { path, len: 4 },
        }];
        write_volume(&mut img, 0, 17 * MIB, 512, 0, &root).unwrap_err();
    }
}
