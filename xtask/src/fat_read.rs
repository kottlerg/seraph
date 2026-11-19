// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/fat_read.rs

//! A reader of the FAT volumes [`crate::fat::write_volume`] writes, built on `fatfs-parse`'s
//! decoders as the `fatfs` service reads them, which checks the structure it walks and returns
//! every file's bytes. `check-disk` reads the ESP and root volumes of `disk.img` with it to
//! compare the ESP with the installed files (`crate::esp::check`), and the disk tooling's tests
//! read back what they wrote.

use std::collections::{BTreeMap, HashSet};
use std::io::{Read, Seek, SeekFrom};

use fat_parse::{FatType, LfnAccum};

use crate::error::{Context, Result, bail, ensure, err};

/// A file's bytes, or a directory, by its path from the root.
#[derive(Debug, PartialEq, Eq)]
pub enum Node
{
    File(Vec<u8>),
    Dir,
}

/// The first byte of a deleted directory entry.
const DELETED: u8 = 0xE5;

/// The attribute bit of a volume label entry.
const ATTR_VOLUME_ID: u8 = 0x08;

/// The attribute bit of a directory entry.
const ATTR_DIRECTORY: u8 = 0x10;

/// Bytes of a directory entry.
const ENTRY_BYTES: usize = 32;

/// The volume a reader walks.
struct Volume<'a, R>
{
    image: &'a mut R,
    offset: u64,
    geo: fat_parse::BpbGeometry,
    fat: Vec<u8>,
    /// Clusters some chain has claimed.
    claimed: HashSet<u32>,
}

/// Every file and directory of the volume at byte `offset` of `image`, whose sectors are
/// `block` bytes, by its path from the root (`/EFI/seraph/kernel`).
///
/// # Errors
/// When the image cannot be read, the boot sector does not decode, the FAT copies differ, a
/// chain holds a cluster that is not a data cluster, does not end in an end-of-chain entry or
/// crosses another (itself included), a subdirectory's `.` or `..` entry names the wrong cluster, a short name repeats
/// in its directory, a name is not UTF-8, a file's size is not its chain's, or an empty file
/// has a cluster.
pub fn read_volume<R: Read + Seek>(
    image: &mut R,
    offset: u64,
    block: u32,
) -> Result<BTreeMap<String, Node>>
{
    let boot = read_at(image, offset, usize::try_from(block)?)?;
    let geo = fat_parse::parse_bpb_geometry(&boot, block)
        .map_err(|_| err!("the boot sector does not decode"))?;
    let sector = u64::from(geo.bytes_per_sector);
    let fat_bytes = u64::from(geo.fat_size)
        .checked_mul(sector)
        .context("the FAT's size overflows")?;
    let mut copies = Vec::new();
    for copy in 0..u64::from(geo.num_fats)
    {
        let at = copy
            .checked_mul(u64::from(geo.fat_size))
            .and_then(|first| first.checked_add(u64::from(geo.reserved_sectors)))
            .and_then(|first| first.checked_mul(sector))
            .and_then(|bytes| bytes.checked_add(offset))
            .context("a FAT copy lies past u64")?;
        copies.push(read_at(image, at, usize::try_from(fat_bytes)?)?);
    }
    ensure!(
        copies.windows(2).all(|pair| pair.first() == pair.last()),
        "the FAT copies differ"
    );
    let mut copies = copies.into_iter();
    let fat = copies.next().context("the volume has no FAT")?;
    let mut volume = Volume {
        image,
        offset,
        fat,
        geo,
        claimed: HashSet::new(),
    };
    let root = match volume.geo.fat_type
    {
        FatType::Fat16 => volume.fixed_root()?,
        FatType::Fat32 => volume.chain_bytes(volume.geo.root_cluster, None)?,
    };
    let mut out = BTreeMap::new();
    volume.walk(&root, "", 0, &mut out)?;
    Ok(out)
}

/// The `len` bytes of `image` at byte `at`.
fn read_at<R: Read + Seek>(image: &mut R, at: u64, len: usize) -> Result<Vec<u8>>
{
    image
        .seek(SeekFrom::Start(at))
        .with_context(|| format!("failed to seek to byte {at} of the image"))?;
    let mut buf = vec![0u8; len];
    image
        .read_exact(&mut buf)
        .with_context(|| format!("failed to read {len} bytes at byte {at} of the image"))?;
    Ok(buf)
}

impl<R: Read + Seek> Volume<'_, R>
{
    /// The `len` bytes from `sector` of the volume.
    fn bytes(&mut self, sector: u32, len: usize) -> Result<Vec<u8>>
    {
        let at = u64::from(sector)
            .checked_mul(u64::from(self.geo.bytes_per_sector))
            .and_then(|bytes| bytes.checked_add(self.offset))
            .context("a sector lies past u64")?;
        read_at(self.image, at, len)
    }

    /// The fixed root directory of a FAT16 volume, which ends where the data region starts.
    fn fixed_root(&mut self) -> Result<Vec<u8>>
    {
        let bytes = u32::from(self.geo.root_entry_count)
            .checked_mul(32)
            .context("the root directory's size overflows")?;
        let sectors = bytes.div_ceil(u32::from(self.geo.bytes_per_sector));
        let first = self
            .geo
            .data_start_sector
            .checked_sub(sectors)
            .context("the root directory starts before the volume")?;
        self.bytes(first, usize::try_from(bytes)?)
    }

    /// The FAT entry of `cluster`.
    fn entry(&self, cluster: u32) -> Result<u32>
    {
        let width = match self.geo.fat_type
        {
            FatType::Fat16 => 2,
            FatType::Fat32 => 4,
        };
        usize::try_from(cluster)
            .ok()
            .and_then(|index| index.checked_mul(width))
            .and_then(|at| fat_parse::read_fat_entry(&self.fat, self.geo.fat_type, at))
            .with_context(|| format!("cluster {cluster} has no FAT entry"))
    }

    /// The bytes of the chain from `first`, its clusters claimed and read in chain order,
    /// wherever they lie (a volume a booted guest or firmware wrote can hold a fragmented
    /// chain); `len` of them for a file, every cluster's for a directory.
    fn chain_bytes(&mut self, first: u32, len: Option<u32>) -> Result<Vec<u8>>
    {
        let eoc = match self.geo.fat_type
        {
            FatType::Fat16 => 0xFFF8,
            FatType::Fat32 => 0x0FFF_FFF8,
        };
        let mut clusters = Vec::new();
        let mut cluster = first;
        loop
        {
            ensure!(
                fat_parse::is_data_cluster(cluster, self.geo.total_clusters),
                "cluster {cluster} of the chain from {first} is not a data cluster"
            );
            ensure!(
                self.claimed.insert(cluster),
                "cluster {cluster} is in two chains"
            );
            clusters.push(cluster);
            let next = self.entry(cluster)?;
            if next >= eoc
            {
                break;
            }
            cluster = next;
        }
        let cluster_bytes = u32::from(self.geo.sectors_per_cluster)
            .checked_mul(u32::from(self.geo.bytes_per_sector))
            .filter(|bytes| *bytes > 0)
            .context("the volume's cluster size is not a positive u32")?;
        if let Some(len) = len
        {
            let count = clusters.len();
            ensure!(
                u32::try_from(count).ok() == Some(len.div_ceil(cluster_bytes)),
                "the chain from {first} is not its file's: {count} clusters for {len} bytes"
            );
        }
        let mut bytes = Vec::new();
        for cluster in clusters
        {
            let sector = fat_parse::cluster_to_sector(
                self.geo.data_start_sector,
                self.geo.sectors_per_cluster,
                cluster,
            );
            bytes.extend(self.bytes(sector, usize::try_from(cluster_bytes)?)?);
        }
        if let Some(len) = len
        {
            bytes.truncate(usize::try_from(len)?);
        }
        Ok(bytes)
    }

    /// Read the directory `raw`, at `path` and cluster `this` (0 for the root), into `out`.
    fn walk(
        &mut self,
        raw: &[u8],
        path: &str,
        this: u32,
        out: &mut BTreeMap<String, Node>,
    ) -> Result<()>
    {
        let mut lfn = LfnAccum::new();
        let mut shorts = HashSet::new();
        let mut subdirs = Vec::new();
        let (slots, _) = raw.as_chunks::<ENTRY_BYTES>();
        for (index, slot) in slots.iter().enumerate()
        {
            if slot[0] == 0
            {
                ensure!(
                    slots.iter().skip(index).flatten().all(|&b| b == 0),
                    "{path}/: entries past the end of the directory"
                );
                break;
            }
            if slot[11] == fat_parse::ATTR_LFN
            {
                lfn.add_lfn_entry(slot);
                continue;
            }
            if slot[0] == DELETED || slot[11] & ATTR_VOLUME_ID != 0
            {
                lfn.reset();
                continue;
            }
            let entry = fat_parse::parse_dir_entry(slot)
                .with_context(|| format!("{path}/: entry {index} does not decode"))?;
            if this != 0 && index < 2
            {
                let dot: &[u8; 11] = if index == 0
                {
                    b".          "
                }
                else
                {
                    b"..         "
                };
                ensure!(&entry.name == dot, "{path}: dot entry {index} is missing");
                ensure!(
                    index != 0 || entry.cluster == this,
                    "{path}: '.' names another cluster"
                );
                continue;
            }
            ensure!(
                shorts.insert(entry.name),
                "{path}/: the short name {:?} repeats",
                String::from_utf8_lossy(&entry.name)
            );
            let name = display_name(&lfn, &entry)
                .with_context(|| format!("{path}/: entry {index} has no UTF-8 name"))?;
            lfn.reset();
            let full = format!("{path}/{name}");
            if entry.attr & ATTR_DIRECTORY != 0
            {
                out.insert(full.clone(), Node::Dir);
                subdirs.push((full, entry.cluster));
            }
            else if entry.size == 0
            {
                ensure!(entry.cluster == 0, "{full}: an empty file has a cluster");
                out.insert(full, Node::File(Vec::new()));
            }
            else
            {
                let bytes = self
                    .chain_bytes(entry.cluster, Some(entry.size))
                    .with_context(|| format!("reading {full}"))?;
                out.insert(full, Node::File(bytes));
            }
        }
        for (sub, cluster) in subdirs
        {
            let raw = self
                .chain_bytes(cluster, None)
                .with_context(|| format!("reading {sub}/"))?;
            let dotdot = raw
                .get(ENTRY_BYTES..)
                .and_then(<[u8]>::first_chunk::<ENTRY_BYTES>)
                .and_then(fat_parse::parse_dir_entry)
                .with_context(|| format!("{sub}: no '..' entry"))?;
            ensure!(dotdot.cluster == this, "{sub}: '..' names another cluster");
            self.walk(&raw, &sub, cluster, out)?;
        }
        Ok(())
    }
}

/// The name of `entry`: the long name `lfn` holds when it is the entry's, else its short name.
fn display_name(lfn: &LfnAccum, entry: &fat_parse::DirEntry) -> Result<String>
{
    let mut name = [0u8; fat_parse::MAX_LFN_UTF8];
    let len = if lfn.validate(&entry.name)
    {
        lfn.assemble_utf8(&mut name)
            .context("the long name does not assemble")?
    }
    else
    {
        entry.write_display_name(&mut name)
    };
    let Some(bytes) = name.get(..len)
    else
    {
        bail!("the name is longer than a name holds");
    };
    Ok(std::str::from_utf8(bytes)?.to_owned())
}

#[cfg(test)]
mod tests
{
    use std::io::Cursor;

    use super::*;
    use crate::fat::{Entry, Kind, write_volume};

    const MIB: u64 = 1024 * 1024;

    /// A 17 MiB FAT16 volume of 512-byte sectors at the start of an image, holding `FILE`,
    /// 5000 bytes, and the decoded geometry.
    fn volume(tag: &str) -> (Vec<u8>, fat_parse::BpbGeometry)
    {
        let dir =
            std::env::temp_dir().join(format!("seraph-fat-read-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("file");
        std::fs::write(&path, vec![7u8; 5000]).unwrap();
        let tree = vec![Entry {
            name: "FILE".to_owned(),
            kind: Kind::File { path, len: 5000 },
        }];
        let mut image = Cursor::new(vec![0u8; usize::try_from(17 * MIB).unwrap()]);
        write_volume(&mut image, 0, 17 * MIB, 512, 1, &tree).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let bytes = image.into_inner();
        let Ok(geo) = fat_parse::parse_bpb_geometry(&bytes[..512], 512)
        else
        {
            panic!("the volume written does not decode");
        };
        (bytes, geo)
    }

    /// The byte offset of the first entry of the fixed root directory of `geo`'s volume.
    fn root_entry(geo: &fat_parse::BpbGeometry) -> usize
    {
        let root_sectors = (u32::from(geo.root_entry_count) * 32).div_ceil(512);
        ((geo.data_start_sector - root_sectors) * 512) as usize
    }

    // Defect caught: a damaged volume read as a tree (check-disk comparing the ESP with
    // files the volume does not hold) or a reader that panics on one rather than failing
    // check-disk with the damage named.
    #[test]
    fn a_damaged_volume_is_an_error_naming_the_damage()
    {
        let (good, geo) = volume("damaged");
        let tree = read_volume(&mut Cursor::new(good.clone()), 0, 512).unwrap();
        assert_eq!(tree.get("/FILE"), Some(&Node::File(vec![7u8; 5000])));

        let refused = |bytes: Vec<u8>, says: &str| {
            let error = read_volume(&mut Cursor::new(bytes), 0, 512).unwrap_err();
            assert!(format!("{error:#}").contains(says), "{error:#}");
        };
        // A boot sector that does not decode.
        let mut bytes = good.clone();
        bytes[510] = 0;
        refused(bytes, "boot sector");
        // FAT copies that differ.
        let mut bytes = good.clone();
        let second = (u32::from(geo.reserved_sectors) + geo.fat_size) * 512;
        bytes[second as usize + 4] ^= 1;
        refused(bytes, "FAT copies differ");
        // A file whose size is not its chain's.
        let mut bytes = good.clone();
        let entry = root_entry(&geo);
        bytes[entry + 28..entry + 32].copy_from_slice(&9000u32.to_le_bytes());
        refused(bytes, "not its file's");
        // An empty file that has a cluster.
        let mut bytes = good.clone();
        bytes[entry + 28..entry + 32].copy_from_slice(&0u32.to_le_bytes());
        refused(bytes, "empty file has a cluster");
        // Two entries sharing a chain.
        let mut bytes = good.clone();
        let copy: Vec<u8> = bytes[entry..entry + 32].to_vec();
        bytes[entry + 32..entry + 64].copy_from_slice(&copy);
        bytes[entry + 32] = b'G';
        refused(bytes, "in two chains");
        // A chain that comes back to its own first cluster.
        let mut bytes = good.clone();
        let first = usize::from(u16::from_le_bytes([bytes[entry + 26], bytes[entry + 27]]));
        for copy in 0..usize::from(geo.num_fats)
        {
            let at = (usize::from(geo.reserved_sectors) + copy * geo.fat_size as usize) * 512
                + (first + 1) * 2;
            bytes[at..at + 2].copy_from_slice(&u16::try_from(first).unwrap().to_le_bytes());
        }
        refused(bytes, "in two chains");
        // A short name twice in one directory.
        let mut bytes = good;
        let copy: Vec<u8> = bytes[entry..entry + 32].to_vec();
        bytes[entry + 32..entry + 64].copy_from_slice(&copy);
        refused(bytes, "repeats");
    }

    // Defect caught: a fragmented chain, which a booted guest's or the firmware's writes leave
    // on a volume, refused or read as the clusters that follow its first (check-disk failing,
    // or comparing the wrong bytes, on an image that has been booted).
    #[test]
    fn a_fragmented_chain_reads_in_chain_order()
    {
        let (mut bytes, geo) = volume("fragmented");
        assert!(matches!(geo.fat_type, FatType::Fat16));
        let size = usize::from(geo.sectors_per_cluster) * 512;
        let data = |cluster: u16| {
            (geo.data_start_sector as usize + (usize::from(cluster) - 2) * (size / 512)) * 512
        };
        let fat = |copy: u32, cluster: u16| {
            ((u32::from(geo.reserved_sectors) + copy * geo.fat_size) * 512) as usize
                + usize::from(cluster) * 2
        };
        // FILE's chain: its first cluster from its entry, then one cluster per `size` bytes.
        let entry = root_entry(&geo);
        let first = u16::from_le_bytes([bytes[entry + 26], bytes[entry + 27]]);
        let count = u16::try_from(5000usize.div_ceil(size)).unwrap();
        assert!(count >= 2);
        let last = first + count - 1;
        let moved = last + 50;
        // Mark each cluster's bytes so that a read of the wrong cluster shows, then move the
        // chain's last cluster past a gap.
        for (mark, cluster) in (first..=last).enumerate()
        {
            bytes[data(cluster)..data(cluster) + size].fill(u8::try_from(mark + 1).unwrap());
        }
        let tail: Vec<u8> = bytes[data(last)..data(last) + size].to_vec();
        bytes[data(moved)..data(moved) + size].copy_from_slice(&tail);
        bytes[data(last)..data(last) + size].fill(0);
        for copy in 0..u32::from(geo.num_fats)
        {
            bytes[fat(copy, last - 1)..fat(copy, last - 1) + 2]
                .copy_from_slice(&moved.to_le_bytes());
            bytes[fat(copy, last)..fat(copy, last) + 2].copy_from_slice(&0u16.to_le_bytes());
            bytes[fat(copy, moved)..fat(copy, moved) + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());
        }
        let tree = read_volume(&mut Cursor::new(bytes), 0, 512).unwrap();
        let mut want = Vec::new();
        for mark in 1..=count
        {
            want.extend(vec![u8::try_from(mark).unwrap(); size]);
        }
        want.truncate(5000);
        assert_eq!(tree.get("/FILE"), Some(&Node::File(want)));
    }
}
