// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! disk.rs
//!
//! Build a GPT disk image from sysroot contents. The image contains three
//! FAT32 partitions: an EFI System Partition (from sysroot/esp/), a Seraph
//! root partition (from sysroot/), and a Seraph data partition (from
//! sysroot/data/) that vfsd auto-mounts at /data.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result};
use boot_protocol::role_guids;

use crate::arch::Arch;
use crate::context::Context as BuildContext;
use crate::util::step;

const SECTOR_SIZE: u64 = 512;

/// ESP partition size. The ESP holds just kernel + bundle + bootloader EFI
/// (init and modules live inside the bundle); 256 MiB leaves comfortable
/// headroom for additional bundle modules.
const ESP_PARTITION_SIZE: u64 = 256 * 1024 * 1024;

/// Root partition size. Holds every installed userspace binary under
/// `/services/` and `/programs/` plus the `/tests/` harness binaries;
/// 512 MiB leaves generous headroom.
const ROOT_PARTITION_SIZE: u64 = 512 * 1024 * 1024;

/// First partition starts at LBA 2048 (1 MiB alignment, standard GPT practice).
const ESP_START_LBA: u64 = 2048;
const ESP_SIZE_LBA: u64 = ESP_PARTITION_SIZE / SECTOR_SIZE;

/// Second partition follows immediately after the first.
const ROOT_START_LBA: u64 = ESP_START_LBA + ESP_SIZE_LBA;
const ROOT_SIZE_LBA: u64 = ROOT_PARTITION_SIZE / SECTOR_SIZE;

/// Data partition size. Backs the `/data` mountpoint (namespace-marker
/// fixture plus svctest scratch space); 256 MiB leaves generous headroom
/// for the test phases' scratch writes.
const DATA_PARTITION_SIZE: u64 = 256 * 1024 * 1024;

/// Third partition follows immediately after the root partition.
const DATA_START_LBA: u64 = ROOT_START_LBA + ROOT_SIZE_LBA;
const DATA_SIZE_LBA: u64 = DATA_PARTITION_SIZE / SECTOR_SIZE;

/// Total image size: partitions + 1 MiB lead-in + 1 MiB trailing GPT backup.
const IMAGE_SIZE: u64 = (DATA_START_LBA + DATA_SIZE_LBA + 2048) * SECTOR_SIZE;

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
/// The image contains three FAT32 partitions:
/// - Partition 1 (ESP, [`ESP_PARTITION_SIZE`]): populated from `sysroot/esp/`
/// - Partition 2 (ROOT, [`ROOT_PARTITION_SIZE`]): populated from `sysroot/`
///   excluding `esp/` and `data/`
/// - Partition 3 (DATA, [`DATA_PARTITION_SIZE`]): populated from `sysroot/data/`
///
/// Partition 2's GPT type-GUID is the arch-specific Seraph root GUID and
/// partition 3's is the arch-neutral Seraph data GUID (see
/// [`boot_protocol::role_guids`]) so vfsd can identify each by role
/// without consulting a config file. vfsd auto-mounts the data partition
/// at `/data`. The data tree is placed only on the data partition, not
/// duplicated onto root; vfsd's fall-through still serves `/data` from
/// root on images that choose to carry it there instead.
pub fn create_disk_image(ctx: &BuildContext, arch: Arch) -> Result<()>
{
    let image_path = ctx.disk_image();
    step(&format!("Creating disk image: {}", image_path.display()));

    // `mkdisk` is the refresh-from-sysroot path — it never authors the
    // bundle. `build` and `compose-bundle` are responsible for producing
    // `bootstrap.bundle` before this point; fail loudly if it is absent
    // rather than producing a disk image the bootloader will refuse.
    let bundle_path = ctx.sysroot_efi_seraph().join("bootstrap.bundle");
    if !bundle_path.exists()
    {
        anyhow::bail!(
            "mkdisk: {} missing — run `cargo xtask build` (default-init bundle) or \
             `cargo xtask compose-bundle --harness {{init,ktest}}` first",
            bundle_path.display()
        );
    }

    // Create zero-filled image file.
    {
        let f = File::create(&image_path).context("failed to create disk image")?;
        f.set_len(IMAGE_SIZE).context("failed to set image size")?;
    }

    // Write GPT (protective MBR + headers + partition entries).
    write_gpt(&image_path, arch)?;

    // Format and populate the ESP from sysroot/esp/.
    let esp_source = ctx.sysroot_esp();
    format_and_populate_partition(&image_path, ESP_START_LBA, ESP_PARTITION_SIZE, &esp_source)?;

    // Format and populate the root partition from sysroot/ (excluding esp/).
    format_and_populate_partition(
        &image_path,
        ROOT_START_LBA,
        ROOT_PARTITION_SIZE,
        &ctx.sysroot,
    )?;

    // Format and populate the data partition from sysroot/data/. vfsd
    // auto-mounts it at /data. The tree is not also written to the root
    // partition (populate_dir skips top-level data/).
    format_and_populate_partition(
        &image_path,
        DATA_START_LBA,
        DATA_PARTITION_SIZE,
        &ctx.sysroot.join("data"),
    )?;

    step("Disk image complete");
    Ok(())
}

/// Deterministic per-partition unique GUIDs for development builds.
///
/// Real installations would mint random per-partition GUIDs at format time.
/// Fixed values here give reproducible disk images. Distinct from the GPT
/// **type** GUIDs (`boot_protocol::role_guids::*`), which identify the
/// partition's role; these identify the specific partition instance.
pub const ESP_UNIQUE_UUID: &str = "a1b2c3d4-e5f6-7890-abcd-ef0123456789";
pub const ROOT_UNIQUE_UUID: &str = "12345678-abcd-ef01-2345-6789abcdef01";
pub const DATA_UNIQUE_UUID: &str = "c0ffee01-2345-6789-abcd-ef0123456789";

/// Return the Seraph root partition type-GUID for `arch`, wrapped as a
/// `gpt::partition_types::Type` ready for `add_partition_at`.
fn seraph_root_type(arch: Arch) -> gpt::partition_types::Type
{
    let bytes = match arch
    {
        Arch::X86_64 => role_guids::SERAPH_ROOT_X86_64,
        Arch::Riscv64 => role_guids::SERAPH_ROOT_RISCV64,
    };
    gpt::partition_types::Type {
        guid: uuid::Uuid::from_bytes_le(bytes),
        os: gpt::partition_types::OperatingSystem::None,
    }
}

/// Return the Seraph data partition type-GUID, wrapped as a
/// `gpt::partition_types::Type` ready for `add_partition_at`. The data
/// GUID is arch-neutral, so this takes no `arch`.
fn seraph_data_type() -> gpt::partition_types::Type
{
    gpt::partition_types::Type {
        guid: uuid::Uuid::from_bytes_le(role_guids::SERAPH_DATA),
        os: gpt::partition_types::OperatingSystem::None,
    }
}

/// Write a GPT partition table with three partitions and deterministic UUIDs.
fn write_gpt(image_path: &Path, arch: Arch) -> Result<()>
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

    // Partition 2: Seraph root, arch-specific type-GUID per
    // `boot_protocol::role_guids`.
    disk.add_partition_at(
        "ROOT",
        2,
        ROOT_START_LBA,
        ROOT_SIZE_LBA,
        seraph_root_type(arch),
        0,
    )
    .context("failed to add ROOT partition")?;

    // Partition 3: Seraph data, arch-neutral type-GUID per
    // `boot_protocol::role_guids`. Flags 0 ⇒ DPS priority 0.
    disk.add_partition_at(
        "DATA",
        3,
        DATA_START_LBA,
        DATA_SIZE_LBA,
        seraph_data_type(),
        0,
    )
    .context("failed to add DATA partition")?;

    // Set deterministic per-partition unique GUIDs for reproducible builds.
    let esp_uuid: uuid::Uuid = ESP_UNIQUE_UUID.parse().expect("invalid ESP_UNIQUE_UUID");
    let root_uuid: uuid::Uuid = ROOT_UNIQUE_UUID.parse().expect("invalid ROOT_UNIQUE_UUID");
    let data_uuid: uuid::Uuid = DATA_UNIQUE_UUID.parse().expect("invalid DATA_UNIQUE_UUID");

    let mut parts = disk.take_partitions();
    if let Some(p) = parts.get_mut(&1)
    {
        p.part_guid = esp_uuid;
    }
    if let Some(p) = parts.get_mut(&2)
    {
        p.part_guid = root_uuid;
    }
    if let Some(p) = parts.get_mut(&3)
    {
        p.part_guid = data_uuid;
    }
    disk.update_partitions(parts)
        .context("failed to update partition UUIDs")?;

    let file = disk.write().context("failed to write GPT")?;
    file.sync_all().context("failed to sync GPT")?;

    Ok(())
}

/// Format a partition as FAT32 and populate it from a source directory.
///
/// Skips build metadata (`.arch`, `NvVars`) and the top-level `esp` and
/// `data` subdirectories, each a mount point with its own partition and so
/// not root content.
fn format_and_populate_partition(
    image_path: &Path,
    start_lba: u64,
    size: u64,
    source_dir: &Path,
) -> Result<()>
{
    let offset = start_lba * SECTOR_SIZE;

    // Format.
    {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(image_path)
            .context("failed to open image for partition format")?;
        let mut slice = PartitionSlice::new(file, offset, size)?;
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
        let slice = PartitionSlice::new(file, offset, size)?;
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

        // `data` is a mount point with its own SERAPH_DATA partition, so it
        // is excluded from the root partition (symmetric with `esp`). Skip
        // it only at the sysroot top level — a nested `data/` elsewhere in
        // the tree is still copied.
        if name_str == "data" && host_dir == sysroot_root
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
