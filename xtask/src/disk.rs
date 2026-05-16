// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! disk.rs
//!
//! Build a GPT disk image from sysroot contents. The image contains two FAT32
//! partitions: an EFI System Partition (populated from sysroot/) and an empty
//! root partition for future use.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result};

use crate::context::Context as BuildContext;
use crate::util::step;

const SECTOR_SIZE: u64 = 512;

/// Both partitions are 192 MiB. Debug binaries each weigh ~14 MiB; the root
/// partition holds ~10 of them plus fixtures, so 128 MiB was insufficient
/// once `fsbench` was added. Release builds remain comfortable well under
/// half of this.
const PARTITION_SIZE: u64 = 192 * 1024 * 1024;

/// First partition starts at LBA 2048 (1 MiB alignment, standard GPT practice).
const ESP_START_LBA: u64 = 2048;
const ESP_SIZE_LBA: u64 = PARTITION_SIZE / SECTOR_SIZE;

/// Second partition follows immediately after the first.
const ROOT_START_LBA: u64 = ESP_START_LBA + ESP_SIZE_LBA;
const ROOT_SIZE_LBA: u64 = PARTITION_SIZE / SECTOR_SIZE;

/// Total image size: partitions + 1 MiB lead-in + 1 MiB trailing GPT backup.
const IMAGE_SIZE: u64 = (ROOT_START_LBA + ROOT_SIZE_LBA + 2048) * SECTOR_SIZE;

/// A read/write/seek view into a byte range of an underlying file.
/// Lets the `fatfs` crate operate on a single partition without knowing
/// about the surrounding GPT layout.
struct PartitionSlice
{
    file: File,
    offset: u64,
    length: u64,
}

impl PartitionSlice
{
    fn new(mut file: File, offset: u64, length: u64) -> io::Result<Self>
    {
        file.seek(SeekFrom::Start(offset))?;
        Ok(PartitionSlice {
            file,
            offset,
            length,
        })
    }
}

impl Read for PartitionSlice
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>
    {
        let pos = self.file.stream_position()?;
        if pos >= self.offset + self.length
        {
            return Ok(0);
        }
        let remaining = (self.offset + self.length - pos) as usize;
        let limit = buf.len().min(remaining);
        self.file.read(&mut buf[..limit])
    }
}

impl Write for PartitionSlice
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize>
    {
        let pos = self.file.stream_position()?;
        if pos >= self.offset + self.length
        {
            return Ok(0);
        }
        let remaining = (self.offset + self.length - pos) as usize;
        let limit = buf.len().min(remaining);
        self.file.write(&buf[..limit])
    }

    fn flush(&mut self) -> io::Result<()>
    {
        self.file.flush()
    }
}

impl Seek for PartitionSlice
{
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64>
    {
        let abs = match pos
        {
            SeekFrom::Start(p) => self.offset + p,
            SeekFrom::End(p) =>
            {
                let end = self.offset + self.length;
                if p >= 0
                {
                    end + p as u64
                }
                else
                {
                    end.checked_sub((-p) as u64).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "seek before start of partition",
                        )
                    })?
                }
            }
            SeekFrom::Current(p) =>
            {
                let cur = self.file.stream_position()?;
                if p >= 0
                {
                    cur + p as u64
                }
                else
                {
                    cur.checked_sub((-p) as u64).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "seek before start of partition",
                        )
                    })?
                }
            }
        };
        self.file.seek(SeekFrom::Start(abs))?;
        Ok(abs - self.offset)
    }
}

/// Create a GPT disk image at `<project_root>/disk.img`.
///
/// The image contains two 64 MiB FAT32 partitions:
/// - Partition 1 (ESP): populated from `sysroot/esp/`
/// - Partition 2 (ROOT): populated from `sysroot/` excluding `esp/`
pub fn create_disk_image(ctx: &BuildContext) -> Result<()>
{
    let image_path = ctx.disk_image();
    step(&format!("Creating disk image: {}", image_path.display()));

    // Create zero-filled image file.
    {
        let f = File::create(&image_path).context("failed to create disk image")?;
        f.set_len(IMAGE_SIZE).context("failed to set image size")?;
    }

    // Write GPT (protective MBR + headers + partition entries).
    write_gpt(&image_path)?;

    // Format and populate the ESP from sysroot/esp/.
    let esp_source = ctx.sysroot_esp();
    format_and_populate_partition(&image_path, ESP_START_LBA, &esp_source)?;

    // Format and populate the root partition from sysroot/ (excluding esp/).
    format_and_populate_partition(&image_path, ROOT_START_LBA, &ctx.sysroot)?;

    step("Disk image complete");
    Ok(())
}

/// Deterministic partition UUIDs for development builds.
///
/// Real installations would use random UUIDs. Fixed values here give us
/// stable `root=UUID=...` in boot.conf without build-time coordination.
pub const ESP_PARTITION_UUID: &str = "a1b2c3d4-e5f6-7890-abcd-ef0123456789";
pub const ROOT_PARTITION_UUID: &str = "12345678-abcd-ef01-2345-6789abcdef01";

/// Write a GPT partition table with two partitions and deterministic UUIDs.
fn write_gpt(image_path: &Path) -> Result<()>
{
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(image_path)
        .context("failed to open image for GPT")?;

    // Write protective MBR.
    let total_sectors = IMAGE_SIZE / SECTOR_SIZE;
    let mbr_size = u32::try_from(total_sectors - 1).unwrap_or(0xFFFF_FFFF);
    let mbr = gpt::mbr::ProtectiveMBR::with_lb_size(mbr_size);
    mbr.overwrite_lba0(&mut file)
        .context("failed to write protective MBR")?;

    // Create GPT disk.
    let mut disk = gpt::GptConfig::default()
        .writable(true)
        .logical_block_size(gpt::disk::LogicalBlockSize::Lb512)
        .change_partition_count(true)
        .create_from_device(file, None)
        .context("failed to create GPT")?;

    // Partition 1: EFI System Partition at LBA 2048 (1 MiB aligned).
    disk.add_partition_at(
        "ESP",
        1,
        ESP_START_LBA,
        ESP_SIZE_LBA,
        gpt::partition_types::EFI,
        0,
    )
    .context("failed to add ESP partition")?;

    // Partition 2: Root (Basic Data) immediately after ESP.
    disk.add_partition_at(
        "ROOT",
        2,
        ROOT_START_LBA,
        ROOT_SIZE_LBA,
        gpt::partition_types::BASIC,
        0,
    )
    .context("failed to add ROOT partition")?;

    // Set deterministic partition UUIDs for reproducible builds.
    let esp_uuid: uuid::Uuid = ESP_PARTITION_UUID
        .parse()
        .expect("invalid ESP_PARTITION_UUID");
    let root_uuid: uuid::Uuid = ROOT_PARTITION_UUID
        .parse()
        .expect("invalid ROOT_PARTITION_UUID");

    let mut parts = disk.take_partitions();
    if let Some(p) = parts.get_mut(&1)
    {
        p.part_guid = esp_uuid;
    }
    if let Some(p) = parts.get_mut(&2)
    {
        p.part_guid = root_uuid;
    }
    disk.update_partitions(parts)
        .context("failed to update partition UUIDs")?;

    let file = disk.write().context("failed to write GPT")?;
    file.sync_all().context("failed to sync GPT")?;

    Ok(())
}

/// Format a partition as FAT32 and populate it from a source directory.
///
/// Skips `.arch`, `NvVars`, and the `esp` subdirectory (which is the ESP
/// mount point, not root content) when populating.
fn format_and_populate_partition(image_path: &Path, start_lba: u64, source_dir: &Path)
-> Result<()>
{
    let offset = start_lba * SECTOR_SIZE;

    // Format.
    {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(image_path)
            .context("failed to open image for partition format")?;
        let mut slice = PartitionSlice::new(file, offset, PARTITION_SIZE)?;
        // 4 KiB clusters align cluster boundaries with the page-granular
        // sector cache in fs/fat: each cluster holds exactly 8 sectors =
        // one PAGE_SIZE, so file data within a cluster is page-contiguous
        // and FS_READ_FRAME can return the cluster's page directly via
        // cap without per-sector translation.
        let opts = fatfs::FormatVolumeOptions::new()
            .bytes_per_cluster(4096)
            .fat_type(fatfs::FatType::Fat32);
        fatfs::format_volume(&mut slice, opts).context("failed to format partition as FAT32")?;
    }

    // Populate (if source directory exists).
    if source_dir.exists()
    {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(image_path)
            .context("failed to open image for partition population")?;
        let slice = PartitionSlice::new(file, offset, PARTITION_SIZE)?;
        let fat = fatfs::FileSystem::new(slice, fatfs::FsOptions::new())
            .context("failed to mount partition")?;
        let root = fat.root_dir();
        populate_dir(&root, source_dir, source_dir)?;
    }

    Ok(())
}

/// Recursively copy a host directory tree into a FAT filesystem directory.
fn populate_dir<T: Read + Write + Seek>(
    fat_dir: &fatfs::Dir<T>,
    host_dir: &Path,
    sysroot_root: &Path,
) -> Result<()>
{
    let mut entries: Vec<_> = fs::read_dir(host_dir)
        .with_context(|| format!("failed to read {}", host_dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|e| e.file_name());

    for entry in entries
    {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip build metadata and the ESP mount point (populated separately).
        if name_str == ".arch" || name_str == "NvVars" || name_str == "esp"
        {
            continue;
        }

        let path = entry.path();
        let ft = entry
            .file_type()
            .with_context(|| format!("failed to get file type: {}", path.display()))?;

        if ft.is_dir()
        {
            fat_dir
                .create_dir(&name_str)
                .with_context(|| format!("failed to create dir in image: {}", name_str))?;
            let sub = fat_dir
                .open_dir(&name_str)
                .with_context(|| format!("failed to open dir in image: {}", name_str))?;
            populate_dir(&sub, &path, sysroot_root)?;
        }
        else if ft.is_file()
        {
            let mut src =
                File::open(&path).with_context(|| format!("failed to open {}", path.display()))?;
            let mut dst = fat_dir
                .create_file(&name_str)
                .with_context(|| format!("failed to create file in image: {}", name_str))?;
            io::copy(&mut src, &mut dst)
                .with_context(|| format!("failed to copy {} into image", path.display()))?;
        }
    }

    Ok(())
}
