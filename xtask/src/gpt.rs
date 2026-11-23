// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/gpt.rs

//! The GUID Partition Table that `mkdisk` writes: a protective MBR, the primary and
//! backup GPT headers, and their partition-entry arrays (UEFI 2.10 § 5.2 and § 5.3).
//!
//! The encoder is pure: [`encode`] turns a [`Table`] into the byte regions an image
//! holds, and [`crate::disk`] writes them. It encodes what xtask authors and nothing
//! more: 128 entries of 128 bytes, no attribute bits, and the disk and partition GUIDs the
//! caller gives, so two authorings of one table are byte-identical. In-tree code replaces a
//! registry crate here (`docs/coding-standards.md` § Dependencies).

use crate::error::{Context, Result, bail, ensure};

/// A GUID in its on-disk byte order: the first three fields little-endian, the last eight
/// bytes as written (the `EFI_GUID` layout). The Seraph role GUIDs of
/// [`boot_protocol::role_guids`] are in this order already.
pub type Guid = [u8; 16];

/// The on-disk bytes of the GUID written `d1-d2-d3-d4`, with `d4` the last two groups
/// of the text form run together.
#[must_use]
pub const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> Guid
{
    let [a0, a1, a2, a3] = d1.to_le_bytes();
    let [b0, b1] = d2.to_le_bytes();
    let [c0, c1] = d3.to_le_bytes();
    let [e0, e1, e2, e3, e4, e5, e6, e7] = d4;
    [
        a0, a1, a2, a3, b0, b1, c0, c1, e0, e1, e2, e3, e4, e5, e6, e7,
    ]
}

/// The EFI System Partition type GUID, `C12A7328-F81F-11D2-BA4B-00A0C93EC93B`.
pub const EFI_SYSTEM_PARTITION: Guid = guid(
    0xC12A_7328,
    0xF81F,
    0x11D2,
    [0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B],
);

/// Entries in each partition-entry array: the UEFI minimum array size of 16 KiB, at
/// [`ENTRY_SIZE`] bytes each.
const ENTRY_COUNT: u32 = 128;

/// Bytes per partition entry.
const ENTRY_SIZE: u32 = 128;

/// Bytes in each partition-entry array: [`ENTRY_COUNT`] entries of [`ENTRY_SIZE`].
const ARRAY_BYTES: usize = 16 * 1024;

/// UTF-16 code units in a partition entry's name field.
const NAME_UNITS: usize = 36;

/// The GPT header signature.
const SIGNATURE: &[u8; 8] = b"EFI PART";

/// GPT header revision 1.0.
const REVISION: u32 = 0x0001_0000;

/// Bytes of the GPT header its CRC covers; the rest of its block is zero.
const HEADER_SIZE: u32 = 92;

/// The protective MBR's partition type.
const PROTECTIVE_TYPE: u8 = 0xEE;

/// One partition of a [`Table`].
pub struct Partition<'a>
{
    /// The partition name, at most 36 UTF-16 code units.
    pub name: &'a str,
    /// The role-identifying partition type GUID.
    pub type_guid: Guid,
    /// The GUID of this partition instance.
    pub unique_guid: Guid,
    /// The partition's first LBA.
    pub first_lba: u64,
    /// The partition's length in blocks, at least one.
    pub blocks: u64,
}

/// A disk's partition table.
pub struct Table<'a>
{
    /// The logical block size in bytes: the unit of every LBA.
    pub block_size: u64,
    /// The disk's size in blocks.
    pub total_blocks: u64,
    /// The disk GUID both headers carry.
    pub disk_guid: Guid,
    /// The partitions, written to entries 1, 2, … in order.
    pub partitions: &'a [Partition<'a>],
}

/// Bytes to write at a byte offset of the image.
#[derive(Debug, PartialEq, Eq)]
pub struct Region
{
    /// Byte offset from the start of the image.
    pub offset: u64,
    /// The bytes written there.
    pub bytes: Vec<u8>,
}

/// Where a table of a given block size and disk size puts its structures, in blocks.
struct Geometry
{
    /// The first LBA a partition may occupy: just past the primary array.
    first_usable: u64,
    /// The last LBA a partition may occupy: just before the backup array.
    last_usable: u64,
    /// The backup array's first LBA.
    backup_array: u64,
    /// The backup header's LBA, the disk's last.
    backup_header: u64,
}

/// The geometry of a `total_blocks`-block disk of `block_size`-byte blocks.
fn geometry(block_size: u64, total_blocks: u64) -> Result<Geometry>
{
    ensure!(
        block_size.is_power_of_two() && block_size >= 512,
        "GPT block size {block_size} is not a power of two of at least 512 bytes"
    );
    let array_bytes = u64::try_from(ARRAY_BYTES).context("entry array size exceeds u64")?;
    let array_blocks = array_bytes.div_ceil(block_size);
    let too_small = || {
        format!("a {total_blocks}-block disk is too small for a GPT at {block_size}-byte blocks")
    };
    let first_usable = array_blocks.checked_add(2).with_context(too_small)?;
    let backup_header = total_blocks.checked_sub(1).with_context(too_small)?;
    let backup_array = backup_header
        .checked_sub(array_blocks)
        .with_context(too_small)?;
    let last_usable = backup_array
        .checked_sub(1)
        .filter(|&last| last >= first_usable)
        .with_context(too_small)?;
    Ok(Geometry {
        first_usable,
        last_usable,
        backup_array,
        backup_header,
    })
}

/// The protective MBR of a `total_blocks`-block disk: one partition of type
/// [`PROTECTIVE_TYPE`] from LBA 1 over the rest of the disk, its size clamped to what the
/// record's 32-bit field holds, padded to one block.
fn protective_mbr(block: usize, total_blocks: u64) -> Vec<u8>
{
    let size = u32::try_from(total_blocks.saturating_sub(1)).unwrap_or(u32::MAX);
    // Boot code, disk signature and the reserved word: 446 bytes, all zero.
    let mut mbr = vec![0u8; 446];
    // The first partition record: not bootable, CHS start 0/0/2, the type, CHS end as large
    // as the field holds, starting LBA 1, and the size in blocks.
    mbr.extend_from_slice(&[0x00, 0x00, 0x02, 0x00, PROTECTIVE_TYPE, 0xFF, 0xFF, 0xFF]);
    mbr.extend_from_slice(&1u32.to_le_bytes());
    mbr.extend_from_slice(&size.to_le_bytes());
    // The other three records are unused.
    mbr.resize(510, 0);
    mbr.extend_from_slice(&[0x55, 0xAA]);
    mbr.resize(block, 0);
    mbr
}

/// One partition entry: the two GUIDs, the LBA range, no attribute bits, and the name in
/// UTF-16LE, zero-padded.
fn entry(p: &Partition<'_>, last_lba: u64) -> Result<Vec<u8>>
{
    let name: Vec<u16> = p.name.encode_utf16().collect();
    ensure!(
        name.len() <= NAME_UNITS,
        "partition name {:?} exceeds {NAME_UNITS} UTF-16 code units",
        p.name
    );
    let mut e = Vec::with_capacity(128);
    e.extend_from_slice(&p.type_guid);
    e.extend_from_slice(&p.unique_guid);
    e.extend_from_slice(&p.first_lba.to_le_bytes());
    e.extend_from_slice(&last_lba.to_le_bytes());
    e.extend_from_slice(&0u64.to_le_bytes());
    for unit in name
    {
        e.extend_from_slice(&unit.to_le_bytes());
    }
    e.resize(128, 0);
    Ok(e)
}

/// The partition-entry array of `table`, refusing a partition outside the usable
/// range, an empty one, or one that overlaps another.
fn entry_array(table: &Table<'_>, geo: &Geometry) -> Result<Vec<u8>>
{
    ensure!(
        table.partitions.len() <= ENTRY_COUNT as usize,
        "{} partitions exceed the {ENTRY_COUNT} entries of the table",
        table.partitions.len()
    );
    let mut array = Vec::with_capacity(ARRAY_BYTES);
    let mut ranges: Vec<(u64, u64)> = Vec::with_capacity(table.partitions.len());
    for p in table.partitions
    {
        let last = p
            .blocks
            .checked_sub(1)
            .and_then(|len| p.first_lba.checked_add(len))
            .with_context(|| format!("partition {} has no blocks, or ends past u64", p.name))?;
        if p.first_lba < geo.first_usable || last > geo.last_usable
        {
            bail!(
                "partition {} (LBAs {}..={last}) lies outside the usable LBAs {}..={}",
                p.name,
                p.first_lba,
                geo.first_usable,
                geo.last_usable
            );
        }
        if let Some((first, end)) = ranges
            .iter()
            .find(|&&(first, end)| p.first_lba <= end && first <= last)
        {
            bail!(
                "partition {} (LBAs {}..={last}) overlaps LBAs {first}..={end}",
                p.name,
                p.first_lba
            );
        }
        ranges.push((p.first_lba, last));
        array.extend_from_slice(&entry(p, last)?);
    }
    array.resize(ARRAY_BYTES, 0);
    Ok(array)
}

/// A GPT header block: the header at `my_lba` naming its partner at `alternate_lba` and its
/// entry array at `entries_lba`, with both CRC32s, padded to one block.
fn header(
    table: &Table<'_>,
    geo: &Geometry,
    block: usize,
    [my_lba, alternate_lba, entries_lba]: [u64; 3],
    entries_crc: u32,
) -> Vec<u8>
{
    let fields = |header_crc: u32| {
        let mut h = Vec::with_capacity(block);
        h.extend_from_slice(SIGNATURE);
        h.extend_from_slice(&REVISION.to_le_bytes());
        h.extend_from_slice(&HEADER_SIZE.to_le_bytes());
        h.extend_from_slice(&header_crc.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());
        h.extend_from_slice(&my_lba.to_le_bytes());
        h.extend_from_slice(&alternate_lba.to_le_bytes());
        h.extend_from_slice(&geo.first_usable.to_le_bytes());
        h.extend_from_slice(&geo.last_usable.to_le_bytes());
        h.extend_from_slice(&table.disk_guid);
        h.extend_from_slice(&entries_lba.to_le_bytes());
        h.extend_from_slice(&ENTRY_COUNT.to_le_bytes());
        h.extend_from_slice(&ENTRY_SIZE.to_le_bytes());
        h.extend_from_slice(&entries_crc.to_le_bytes());
        h
    };
    // The header CRC covers the header with its own CRC field zero.
    let mut h = fields(crc32(&fields(0)));
    h.resize(block, 0);
    h
}

/// The regions an image holding `table` carries: the protective MBR at LBA 0, the
/// primary header at LBA 1 and its entry array from LBA 2, and the backup entry array and
/// header in the disk's last blocks. Every other byte of the image is the caller's.
///
/// # Errors
/// Fails when the block size is not a power of two of at least 512 bytes, the disk is too
/// small to hold both tables and one usable block, there are more partitions than entries, a
/// partition has no blocks, lies outside the usable LBAs or overlaps another, or a name is
/// longer than the entry's name field.
pub fn encode(table: &Table<'_>) -> Result<Vec<Region>>
{
    let geo = geometry(table.block_size, table.total_blocks)?;
    let block = usize::try_from(table.block_size).context("GPT block size exceeds usize")?;
    let array = entry_array(table, &geo)?;
    let entries_crc = crc32(&array);
    let at = |lba: u64| {
        lba.checked_mul(table.block_size)
            .context("GPT structure offset exceeds u64")
    };
    let primary = header(table, &geo, block, [1, geo.backup_header, 2], entries_crc);
    let backup = header(
        table,
        &geo,
        block,
        [geo.backup_header, 1, geo.backup_array],
        entries_crc,
    );
    Ok(vec![
        Region {
            offset: 0,
            bytes: protective_mbr(block, table.total_blocks),
        },
        Region {
            offset: at(1)?,
            bytes: primary,
        },
        Region {
            offset: at(2)?,
            bytes: array.clone(),
        },
        Region {
            offset: at(geo.backup_array)?,
            bytes: array,
        },
        Region {
            offset: at(geo.backup_header)?,
            bytes: backup,
        },
    ])
}

/// The CRC-32 GPT headers carry: IEEE 802.3, reflected, initial value and final XOR all ones.
fn crc32(bytes: &[u8]) -> u32
{
    let mut crc = u32::MAX;
    for &byte in bytes
    {
        crc ^= u32::from(byte);
        for _ in 0..8
        {
            let low = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & low);
        }
    }
    !crc
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    const TYPE_A: Guid = guid(0x1111_1111, 0x2222, 0x3333, [4, 4, 5, 5, 5, 5, 5, 5]);
    const TYPE_B: Guid = guid(
        0xAAAA_AAAA,
        0xBBBB,
        0xCCCC,
        [0xD, 0xD, 0xE, 0xE, 0xE, 0xE, 0xE, 0xE],
    );
    const DISK: Guid = guid(0x0123_4567, 0x89AB, 0xCDEF, [1, 2, 3, 4, 5, 6, 7, 8]);

    fn part(name: &str, type_guid: Guid, unique: u8, first_lba: u64, blocks: u64) -> Partition<'_>
    {
        Partition {
            name,
            type_guid,
            unique_guid: [unique; 16],
            first_lba,
            blocks,
        }
    }

    fn table<'a>(block_size: u64, total_blocks: u64, partitions: &'a [Partition<'a>]) -> Table<'a>
    {
        Table {
            block_size,
            total_blocks,
            disk_guid: DISK,
            partitions,
        }
    }

    /// The image `regions` make of a zeroed disk of `table`'s size.
    fn image(table: &Table<'_>) -> Vec<u8>
    {
        let mut disk = vec![0u8; usize::try_from(table.block_size * table.total_blocks).unwrap()];
        for r in encode(table).unwrap()
        {
            let at = usize::try_from(r.offset).unwrap();
            disk[at..at + r.bytes.len()].copy_from_slice(&r.bytes);
        }
        disk
    }

    /// The block at `lba` of `disk`.
    fn block(disk: &[u8], block_size: u64, lba: u64) -> &[u8]
    {
        let at = usize::try_from(lba * block_size).unwrap();
        &disk[at..at + usize::try_from(block_size).unwrap()]
    }

    fn u32_at(bytes: &[u8], at: usize) -> u32
    {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    fn u64_at(bytes: &[u8], at: usize) -> u64
    {
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
    }

    /// The used entries of the table whose header is at `lba`, read by vfsd's parser.
    fn vfsd_entries(disk: &[u8], block_size: u64, lba: u64) -> Vec<vfsd_gpt::GptEntry>
    {
        let Ok(header) = vfsd_gpt::parse_header(block(disk, block_size, lba), lba)
        else
        {
            panic!("vfsd-gpt refused the header at LBA {lba}");
        };
        let scan = vfsd_gpt::collect_partitions(&header, |lba, buf| {
            buf.copy_from_slice(block(disk, block_size, lba));
            true
        });
        assert_eq!(scan.stop, None);
        scan.entries
    }

    #[test]
    fn crc32_matches_the_ieee_check_value()
    {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(&[]), 0);
    }

    #[test]
    fn guid_writes_the_first_three_fields_little_endian()
    {
        // The EFI System Partition type GUID as every GPT on disk holds it.
        assert_eq!(
            EFI_SYSTEM_PARTITION,
            [
                0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E,
                0xC9, 0x3B
            ]
        );
    }

    #[test]
    fn vfsd_reads_every_partition_at_either_block_size()
    {
        for block_size in [512u64, 4096]
        {
            let first = 16384 / block_size + 2;
            let parts = [
                part("ESP", EFI_SYSTEM_PARTITION, 1, first, 10),
                part("ROOT", TYPE_A, 2, first + 10, 20),
                part("SWAP", TYPE_B, 3, first + 40, 5),
            ];
            let t = table(block_size, 200, &parts);
            let disk = image(&t);

            let expected: Vec<vfsd_gpt::GptEntry> = parts
                .iter()
                .map(|p| vfsd_gpt::GptEntry {
                    type_guid: p.type_guid,
                    uuid: p.unique_guid,
                    first_lba: p.first_lba,
                    length_lba: p.blocks,
                    attributes: 0,
                })
                .collect();
            assert_eq!(vfsd_entries(&disk, block_size, 1), expected, "{block_size}");

            // vfsd reads the primary GPT whole, and the backup alone when the
            // primary header is damaged, each with its CRC32s and MyLBA
            // accepted.
            let blocks = disk.len() as u64 / block_size;
            let read = |disk: &[u8]| {
                vfsd_gpt::read_gpt(usize::try_from(block_size).unwrap(), blocks, |lba, buf| {
                    buf.copy_from_slice(block(disk, block_size, lba));
                    true
                })
                .unwrap_or_else(|faults| panic!("vfsd refused both GPTs: {faults:?}"))
            };
            let primary = read(&disk);
            assert_eq!(primary.copy, vfsd_gpt::GptCopy::Primary, "{block_size}");
            assert_eq!(primary.scan.entries, expected, "{block_size}");
            let mut damaged = disk.clone();
            damaged[usize::try_from(block_size).unwrap() + 16] ^= 1;
            let backup = read(&damaged);
            assert_eq!(backup.copy, vfsd_gpt::GptCopy::Backup, "{block_size}");
            assert_eq!(backup.scan.entries, expected, "{block_size}");

            // The second entry's name, in UTF-16LE, zero-padded.
            let entries = block(&disk, block_size, 2);
            let mut name = [0u8; 72];
            name[..8].copy_from_slice(&[b'R', 0, b'O', 0, b'O', 0, b'T', 0]);
            assert_eq!(&entries[128 + 56..256], &name[..]);
        }
    }

    #[test]
    fn each_header_carries_valid_crcs_and_names_the_other()
    {
        for block_size in [512u64, 4096]
        {
            let array_blocks = 16384 / block_size;
            let parts = [part("A", TYPE_A, 1, array_blocks + 2, 3)];
            let total = 100;
            let disk = image(&table(block_size, total, &parts));
            let backup_array = total - 1 - array_blocks;
            for (my, alternate, entries) in [(1, total - 1, 2), (total - 1, 1, backup_array)]
            {
                let h = block(&disk, block_size, my);
                assert_eq!(&h[..8], b"EFI PART");
                assert_eq!(u32_at(h, 8), 0x0001_0000);
                assert_eq!(u32_at(h, 12), 92);
                let mut zeroed = h[..92].to_vec();
                zeroed[16..20].fill(0);
                assert_eq!(u32_at(h, 16), crc32(&zeroed), "header CRC at LBA {my}");
                assert!(h[92..].iter().all(|&b| b == 0));
                assert_eq!(u64_at(h, 24), my);
                assert_eq!(u64_at(h, 32), alternate);
                assert_eq!(u64_at(h, 40), array_blocks + 2);
                assert_eq!(u64_at(h, 48), backup_array - 1);
                assert_eq!(&h[56..72], &DISK);
                assert_eq!(u64_at(h, 72), entries);
                assert_eq!((u32_at(h, 80), u32_at(h, 84)), (128, 128));
                let at = usize::try_from(entries * block_size).unwrap();
                assert_eq!(
                    u32_at(h, 88),
                    crc32(&disk[at..at + 16384]),
                    "entry array CRC at LBA {my}"
                );
            }
        }
    }

    #[test]
    fn the_protective_mbr_covers_the_disk_from_lba_1_and_clamps_its_size()
    {
        for (total, size) in [(200u64, 199u32), (u64::from(u32::MAX) + 10, u32::MAX)]
        {
            let mbr = protective_mbr(4096, total);
            assert_eq!(mbr.len(), 4096);
            assert_eq!(mbr[450], 0xEE);
            assert_eq!(u32_at(&mbr, 454), 1);
            assert_eq!(u32_at(&mbr, 458), size);
            assert_eq!(&mbr[510..512], &[0x55, 0xAA]);
            assert!(mbr[..446].iter().all(|&b| b == 0));
            assert!(mbr[462..510].iter().all(|&b| b == 0));
            assert!(mbr[512..].iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn encode_takes_a_partition_filling_the_usable_lbas_and_a_full_length_name()
    {
        // 68 blocks at 512 bytes: MBR, header, 32-block array, LBA 34 alone usable, 32-block
        // backup array, backup header.
        let name = "N".repeat(36);
        let parts = [part(&name, TYPE_A, 1, 34, 1)];
        let disk = image(&table(512, 68, &parts));
        assert_eq!(vfsd_entries(&disk, 512, 1).len(), 1);
    }

    #[test]
    fn encode_refuses_a_table_it_cannot_write()
    {
        let ok = |first, blocks| part("P", TYPE_A, 1, first, blocks);
        let long = "N".repeat(37);
        let many: Vec<Partition<'_>> = (0..129).map(|i| ok(34 + i, 1)).collect();
        let cases: [(u64, u64, &[Partition<'_>]); 10] = [
            (1000, 200, &[]),
            (256, 200, &[]),
            (512, 67, &[]),
            (512, 0, &[]),
            (512, 400, &many),
            (512, 200, &[ok(40, 0)]),
            (512, 200, &[ok(33, 2)]),
            (512, 200, &[ok(160, 8)]),
            (512, 200, &[ok(40, 10), ok(49, 2)]),
            (512, 200, &[part(&long, TYPE_A, 1, 40, 1)]),
        ];
        for (i, (block_size, total, parts)) in cases.into_iter().enumerate()
        {
            assert!(
                encode(&table(block_size, total, parts)).is_err(),
                "case {i}"
            );
        }
        // The last usable LBA of a 200-block disk at 512 bytes is 166, which 8 blocks from 160
        // pass and 7 reach.
        encode(&table(512, 200, &[ok(160, 7)])).unwrap();
    }
}
