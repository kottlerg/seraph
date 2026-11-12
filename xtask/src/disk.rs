// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/disk.rs

//! Build GPT disk images from sysroot contents. The images hold three FAT
//! partitions: an EFI System Partition (from sysroot/esp/), a Seraph root
//! partition (from sysroot/), and a Seraph data partition (from
//! sysroot/data/) that vfsd auto-mounts at /data. `disk.img` carries all
//! three, or the first two with the data partition alone on a second image;
//! the logical block size, 512 or 4096 bytes, is chosen per authoring.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use boot_protocol::role_guids;
use clap::ValueEnum;

use crate::arch::Arch;
use crate::context::Context as BuildContext;
use crate::util::step;

/// ESP partition size. Holds the kernel, the boot bundle (init + modules),
/// and the bootloader EFI. 64 MiB covers these with headroom for `--debug`
/// debuginfo and future bundle modules.
const ESP_PARTITION_SIZE: u64 = 64 * 1024 * 1024;

/// Root partition size. Holds every installed userspace binary under
/// `/services/` and `/programs/` plus the `/tests/` harness binaries. With
/// debuginfo off by default the tree is ~10 MiB; 192 MiB covers a full
/// `--debug` rebuild and ample future components.
const ROOT_PARTITION_SIZE: u64 = 192 * 1024 * 1024;

/// Data partition size. Backs the `/data` mountpoint (namespace-marker
/// fixture plus svctest scratch space); 256 MiB leaves generous headroom
/// for the test phases' scratch writes.
const DATA_PARTITION_SIZE: u64 = 256 * 1024 * 1024;

/// Bytes before the first partition and after the last: the first partition
/// starts 1 MiB in (standard GPT alignment, past the primary header and
/// entry array at either block size), and the last 1 MiB holds the backup
/// entry array and header.
const IMAGE_MARGIN: u64 = 1024 * 1024;

/// The GPT header signature, at the start of LBA 1.
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";

/// Logical block size of an authored image: the unit of its GPT LBAs and the
/// sector size of each of its FAT volumes. A launch presents the disk device
/// at the same size ([`logical_block_size`] reads it back from the image).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum BlockSize
{
    /// 512-byte blocks — the default.
    #[default]
    #[value(name = "512")]
    B512,
    /// 4096-byte blocks (4Kn).
    #[value(name = "4096")]
    B4096,
}

impl BlockSize
{
    /// The block size in bytes.
    #[must_use]
    pub fn bytes(self) -> u64
    {
        match self
        {
            Self::B512 => 512,
            Self::B4096 => 4096,
        }
    }

    /// Whole blocks in `bytes`, rounded down.
    #[must_use]
    pub fn blocks(self, bytes: u64) -> u64
    {
        match self
        {
            Self::B512 => bytes / 512,
            Self::B4096 => bytes / 4096,
        }
    }

    fn gpt(self) -> gpt::disk::LogicalBlockSize
    {
        match self
        {
            Self::B512 => gpt::disk::LogicalBlockSize::Lb512,
            Self::B4096 => gpt::disk::LogicalBlockSize::Lb4096,
        }
    }

    fn fat_sector(self) -> u16
    {
        match self
        {
            Self::B512 => 512,
            Self::B4096 => 4096,
        }
    }
}

/// Which image carries the Seraph data partition.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DataPlacement
{
    /// `disk.img` carries all three partitions — the default.
    #[default]
    MainImage,
    /// `disk.img` carries the ESP and root; `disk-data.img` carries the data
    /// partition alone, for a boot that attaches it as a second disk.
    SecondImage,
}

/// The images [`create_disk_image`] authors and their block size.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DiskLayout
{
    /// Logical block size of every authored image.
    pub block_size: BlockSize,
    /// Which image carries the data partition.
    pub data: DataPlacement,
}

/// One FAT partition of an image: its GPT name, type and unique GUIDs, size,
/// and the host directory it is populated from (skipped when absent).
struct Volume
{
    name: &'static str,
    type_guid: gpt::partition_types::Type,
    unique_uuid: &'static str,
    bytes: u64,
    source: PathBuf,
}

/// The host directories the three partitions are populated from.
struct Sources
{
    esp: PathBuf,
    root: PathBuf,
    data: PathBuf,
}

/// A read/write/seek view into a byte range of an underlying file.
/// Lets the `fatfs` crate operate on a single partition without knowing
/// about the surrounding GPT layout.
struct PartitionSlice
{
    file: File,
    /// Absolute file offset of the partition's first byte.
    offset: u64,
    /// Absolute file offset one past the partition's last byte.
    end: u64,
}

impl PartitionSlice
{
    fn new(mut file: File, offset: u64, length: u64) -> io::Result<Self>
    {
        let end = offset.checked_add(length).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "partition extends past u64")
        })?;
        file.seek(SeekFrom::Start(offset))?;
        Ok(PartitionSlice { file, offset, end })
    }

    /// Bytes from the file position to the partition's end: zero at or past
    /// it, capped at `usize::MAX`.
    fn remaining(&mut self) -> io::Result<usize>
    {
        let pos = self.file.stream_position()?;
        Ok(usize::try_from(self.end.saturating_sub(pos)).unwrap_or(usize::MAX))
    }
}

impl Read for PartitionSlice
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>
    {
        let limit = buf.len().min(self.remaining()?);
        self.file.read(buf.get_mut(..limit).unwrap_or_default())
    }
}

impl Write for PartitionSlice
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize>
    {
        let limit = buf.len().min(self.remaining()?);
        self.file.write(buf.get(..limit).unwrap_or_default())
    }

    fn flush(&mut self) -> io::Result<()>
    {
        self.file.flush()
    }
}

impl Seek for PartitionSlice
{
    /// Seeks within the partition. A target before the partition's first
    /// byte, or one `u64` cannot hold, is an error that leaves the position
    /// unchanged.
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64>
    {
        let target = match pos
        {
            SeekFrom::Start(p) => self.offset.checked_add(p),
            SeekFrom::End(p) => self.end.checked_add_signed(p),
            SeekFrom::Current(p) => self.file.stream_position()?.checked_add_signed(p),
        };
        let Some((abs, relative)) =
            target.and_then(|abs| Some((abs, abs.checked_sub(self.offset)?)))
        else
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek outside the partition",
            ));
        };
        self.file.seek(SeekFrom::Start(abs))?;
        Ok(relative)
    }
}

/// Create the GPT disk image at `<project_root>/disk.img`, and, when the
/// layout places the data partition on a second image, `disk-data.img`
/// beside it.
///
/// The images hold three FAT partitions:
/// - ESP ([`ESP_PARTITION_SIZE`]): populated from `sysroot/esp/`
/// - ROOT ([`ROOT_PARTITION_SIZE`]): populated from `sysroot/`
///   excluding `esp/` and `data/`
/// - DATA ([`DATA_PARTITION_SIZE`]): populated from `sysroot/data/`
///
/// `disk.img` carries the ESP and ROOT, and DATA too unless `layout.data` is
/// [`DataPlacement::SecondImage`], which puts DATA alone on `disk-data.img`.
/// Authoring with DATA on `disk.img` removes a `disk-data.img` an earlier
/// authoring left, so a stale second copy of the data partition cannot be
/// attached. Every image's GPT LBAs and FAT sectors are `layout.block_size`
/// bytes.
///
/// ROOT's GPT type-GUID is the arch-specific Seraph root GUID and DATA's is
/// the arch-neutral Seraph data GUID (see [`boot_protocol::role_guids`]) so
/// vfsd can identify each by role, on whichever disk holds it, without
/// consulting a config file. vfsd auto-mounts the data partition at
/// `/data`. The data tree is placed only on the data partition, not
/// duplicated onto root; vfsd's fall-through still serves `/data` from
/// root on images that choose to carry it there instead.
pub fn create_disk_image(ctx: &BuildContext, arch: Arch, layout: DiskLayout) -> Result<()>
{
    let image_path = ctx.disk_image();
    step(&format!(
        "Creating disk image: {} ({}-byte blocks)",
        image_path.display(),
        layout.block_size.bytes()
    ));

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

    let sources = Sources {
        esp: ctx.sysroot_esp(),
        root: ctx.sysroot.clone(),
        data: ctx.sysroot.join("data"),
    };
    let data_image = ctx.data_disk_image();
    author_images(&image_path, &data_image, arch, layout, &sources)?;
    if layout.data == DataPlacement::SecondImage
    {
        step(&format!("Data partition image: {}", data_image.display()));
    }

    step("Disk image complete");
    Ok(())
}

/// Author `main_image`, and `data_image` when `layout` places the data
/// partition there, from `sources`.
fn author_images(
    main_image: &Path,
    data_image: &Path,
    arch: Arch,
    layout: DiskLayout,
    sources: &Sources,
) -> Result<()>
{
    let esp = Volume {
        name: "ESP",
        type_guid: gpt::partition_types::EFI,
        unique_uuid: ESP_UNIQUE_UUID,
        bytes: ESP_PARTITION_SIZE,
        source: sources.esp.clone(),
    };
    let root = Volume {
        name: "ROOT",
        type_guid: seraph_root_type(arch),
        unique_uuid: ROOT_UNIQUE_UUID,
        bytes: ROOT_PARTITION_SIZE,
        source: sources.root.clone(),
    };
    // The data tree is not also written to the root partition
    // (populate_dir skips top-level data/).
    let data = Volume {
        name: "DATA",
        type_guid: seraph_data_type(),
        unique_uuid: DATA_UNIQUE_UUID,
        bytes: DATA_PARTITION_SIZE,
        source: sources.data.clone(),
    };

    match layout.data
    {
        DataPlacement::MainImage =>
        {
            write_image(main_image, layout.block_size, &[esp, root, data])?;
            if data_image.exists()
            {
                fs::remove_file(data_image)
                    .with_context(|| format!("failed to remove stale {}", data_image.display()))?;
            }
        }
        DataPlacement::SecondImage =>
        {
            write_image(main_image, layout.block_size, &[esp, root])?;
            write_image(data_image, layout.block_size, &[data])?;
        }
    }
    Ok(())
}

/// Start LBA of each of `volumes`, laid end to end after [`IMAGE_MARGIN`],
/// and the image's total size in bytes (with the trailing margin).
fn plan(volumes: &[Volume], block_size: BlockSize) -> Result<(Vec<u64>, u64)>
{
    let mut offset = IMAGE_MARGIN;
    let mut starts = Vec::with_capacity(volumes.len());
    for v in volumes
    {
        starts.push(block_size.blocks(offset));
        offset = offset
            .checked_add(v.bytes)
            .context("disk image layout exceeds u64")?;
    }
    let total = offset
        .checked_add(IMAGE_MARGIN)
        .context("disk image layout exceeds u64")?;
    Ok((starts, total))
}

/// Write a zero-filled image at `path` holding `volumes` as GPT partitions
/// 1, 2, … in order, each formatted FAT32 and populated from its source.
fn write_image(path: &Path, block_size: BlockSize, volumes: &[Volume]) -> Result<()>
{
    let (starts, image_size) = plan(volumes, block_size)?;
    {
        let f = File::create(path)
            .with_context(|| format!("failed to create disk image {}", path.display()))?;
        f.set_len(image_size).context("failed to set image size")?;
    }

    write_gpt(path, block_size, image_size, volumes, &starts)?;

    for (volume, start_lba) in volumes.iter().zip(&starts)
    {
        format_and_populate_partition(
            path,
            start_lba
                .checked_mul(block_size.bytes())
                .context("partition offset exceeds u64")?,
            volume.bytes,
            block_size,
            &volume.source,
        )?;
    }
    Ok(())
}

/// The logical block size of the GPT image at `path`: 512 or 4096, whichever
/// LBA 1 the `EFI PART` header sits at.
///
/// # Errors
/// Fails when the file cannot be read or carries no GPT header at either
/// block size.
pub fn logical_block_size(path: &Path) -> Result<u32>
{
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut head = Vec::new();
    file.take(4096u64.saturating_add(GPT_SIGNATURE.len() as u64))
        .read_to_end(&mut head)
        .with_context(|| format!("failed to read {}", path.display()))?;
    gpt_block_size(&head).with_context(|| {
        format!(
            "{} carries no GPT header at LBA 1 for 512- or 4096-byte blocks",
            path.display()
        )
    })
}

/// The block size a second disk's device presents: `override_size` when the
/// caller set one, else the size of the image at `path`.
///
/// # Errors
/// Fails as [`logical_block_size`] does when no override is given.
pub fn second_disk_block_size(path: &Path, override_size: Option<u32>) -> Result<u32>
{
    override_size.map_or_else(|| logical_block_size(path), Ok)
}

/// The block size whose LBA 1 starts with the GPT signature in `head`, the
/// first bytes of an image. 512 is checked first: a 512-byte-block image's
/// offset 4096 lies in its partition entry array, and a 4Kn image's offset
/// 512 lies in the zeroed tail of its protective MBR block.
fn gpt_block_size(head: &[u8]) -> Option<u32>
{
    [512u32, 4096].into_iter().find(|&size| {
        usize::try_from(size).is_ok_and(|at| {
            at.checked_add(GPT_SIGNATURE.len())
                .and_then(|to| head.get(at..to))
                == Some(GPT_SIGNATURE.as_slice())
        })
    })
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

/// Write the protective MBR and a GPT holding `volumes` as partitions 1, 2,
/// … at `starts`, with their deterministic unique GUIDs.
fn write_gpt(
    image_path: &Path,
    block_size: BlockSize,
    image_size: u64,
    volumes: &[Volume],
    starts: &[u64],
) -> Result<()>
{
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(image_path)
        .context("failed to open image for GPT")?;

    // Write protective MBR.
    let total_lbas = block_size.blocks(image_size);
    let mbr_size = u32::try_from(total_lbas.saturating_sub(1)).unwrap_or(0xFFFF_FFFF);
    let mbr = gpt::mbr::ProtectiveMBR::with_lb_size(mbr_size);
    mbr.overwrite_lba0(&mut file)
        .context("failed to write protective MBR")?;

    // Create GPT disk.
    let mut disk = gpt::GptConfig::default()
        .writable(true)
        .logical_block_size(block_size.gpt())
        .change_partition_count(true)
        .create_from_device(file, None)
        .context("failed to create GPT")?;

    // Flags 0 ⇒ DPS priority 0.
    for ((volume, &start_lba), id) in volumes.iter().zip(starts).zip(1u32..)
    {
        disk.add_partition_at(
            volume.name,
            id,
            start_lba,
            block_size.blocks(volume.bytes),
            volume.type_guid.clone(),
            0,
        )
        .with_context(|| format!("failed to add {} partition", volume.name))?;
    }

    // Set deterministic per-partition unique GUIDs for reproducible builds.
    let mut parts = disk.take_partitions();
    for (volume, id) in volumes.iter().zip(1u32..)
    {
        let uuid: uuid::Uuid = volume
            .unique_uuid
            .parse()
            .with_context(|| format!("invalid {} unique UUID", volume.name))?;
        if let Some(p) = parts.get_mut(&id)
        {
            p.part_guid = uuid;
        }
    }
    disk.update_partitions(parts)
        .context("failed to update partition UUIDs")?;

    let file = disk.write().context("failed to write GPT")?;
    file.sync_all().context("failed to sync GPT")?;

    Ok(())
}

/// Format a partition as FAT and populate it from a source directory.
///
/// Skips build metadata (`.arch`, `NvVars`) and the top-level `esp` and
/// `data` subdirectories, each a mount point with its own partition and so
/// not root content.
fn format_and_populate_partition(
    image_path: &Path,
    offset: u64,
    size: u64,
    block_size: BlockSize,
    source_dir: &Path,
) -> Result<()>
{
    // Format.
    {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(image_path)
            .context("failed to open image for partition format")?;
        let mut slice = PartitionSlice::new(file, offset, size)?;
        // 4 KiB clusters align cluster boundaries with the page-granular
        // sector cache in fs/fat: each cluster is one PAGE_SIZE (8 sectors
        // of 512 bytes, or one 4Kn sector), so file data within a cluster
        // is page-contiguous and FS_READ_FRAME can return the cluster's
        // page directly via cap without per-sector translation. The sector
        // size is the image's logical block size, which fs/fat requires
        // the volume's to equal.
        let opts = fatfs::FormatVolumeOptions::new()
            .bytes_per_sector(block_size.fat_sector())
            .bytes_per_cluster(4096)
            .fat_type(fatfs::FatType::Fat32);
        fatfs::format_volume(&mut slice, opts).context("failed to format partition as FAT")?;
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
    entries.sort_by_key(std::fs::DirEntry::file_name);

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
                .with_context(|| format!("failed to create dir in image: {name_str}"))?;
            let sub = fat_dir
                .open_dir(&name_str)
                .with_context(|| format!("failed to open dir in image: {name_str}"))?;
            populate_dir(&sub, &path, sysroot_root)?;
        }
        else if ft.is_file()
        {
            let mut src =
                File::open(&path).with_context(|| format!("failed to open {}", path.display()))?;
            let mut dst = fat_dir
                .create_file(&name_str)
                .with_context(|| format!("failed to create file in image: {name_str}"))?;
            io::copy(&mut src, &mut dst)
                .with_context(|| format!("failed to copy {} into image", path.display()))?;
        }
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn partition_slice_seeks_stay_inside_the_partition()
    {
        let scratch = Scratch::new("slice-seek");
        let path = scratch.0.join("f.img");
        fs::write(&path, [0u8; 32]).unwrap();
        let open = || File::open(&path).unwrap();

        // A partition whose end `u64` cannot hold is refused.
        assert!(PartitionSlice::new(open(), 8, u64::MAX).is_err());

        // Partition bytes 8..24 of the file.
        let mut slice = PartitionSlice::new(open(), 8, 16).unwrap();
        assert_eq!(slice.seek(SeekFrom::Start(4)).unwrap(), 4);
        assert_eq!(slice.seek(SeekFrom::Current(-4)).unwrap(), 0);
        assert_eq!(slice.seek(SeekFrom::End(-16)).unwrap(), 0);
        assert_eq!(slice.seek(SeekFrom::End(0)).unwrap(), 16);

        // Before the partition's first byte, though inside the file.
        slice.seek(SeekFrom::Start(2)).unwrap();
        slice.seek(SeekFrom::Current(-3)).unwrap_err();
        slice.seek(SeekFrom::End(-17)).unwrap_err();
        // A failed seek leaves the position unchanged.
        assert_eq!(slice.stream_position().unwrap(), 2);

        // Past what `u64` holds.
        slice.seek(SeekFrom::Start(u64::MAX)).unwrap_err();
        assert_eq!(slice.stream_position().unwrap(), 2);
    }

    /// A scratch directory unique to this process and `name`, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch
    {
        fn new(name: &str) -> Self
        {
            let dir =
                std::env::temp_dir().join(format!("seraph-disk-{}-{name}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        /// Sources under the scratch directory: an absent ESP and root tree
        /// (formatted, not populated) and a data tree holding `test.txt`.
        fn sources(&self) -> Sources
        {
            let data = self.0.join("data");
            fs::create_dir_all(&data).unwrap();
            fs::write(data.join("test.txt"), b"seraph").unwrap();
            Sources {
                esp: self.0.join("no-esp"),
                root: self.0.join("no-root"),
                data,
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

    /// `(first_lba, type GUID)` of each partition, in partition order, read
    /// back through the gpt crate at `block_size`.
    fn read_partitions(path: &Path, block_size: BlockSize) -> Vec<(u64, uuid::Uuid)>
    {
        let disk = gpt::GptConfig::new()
            .logical_block_size(block_size.gpt())
            .open(path)
            .unwrap();
        disk.partitions()
            .values()
            .map(|p| (p.first_lba, p.part_type_guid.guid))
            .collect()
    }

    /// The FAT boot sector's `BPB_BytsPerSec` of the volume at `offset`.
    fn bytes_per_sector(path: &Path, offset: u64) -> u16
    {
        let mut file = File::open(path).unwrap();
        file.seek(SeekFrom::Start(offset + 11)).unwrap();
        let mut field = [0u8; 2];
        file.read_exact(&mut field).unwrap();
        u16::from_le_bytes(field)
    }

    #[test]
    fn image_puts_gpt_lbas_and_fat_sectors_at_the_requested_block_size()
    {
        for block_size in [BlockSize::B512, BlockSize::B4096]
        {
            let scratch = Scratch::new(&format!("size-{}", block_size.bytes()));
            let main = scratch.0.join("disk.img");
            let layout = DiskLayout {
                block_size,
                data: DataPlacement::MainImage,
            };
            author_images(
                &main,
                &scratch.0.join("disk-data.img"),
                Arch::X86_64,
                layout,
                &scratch.sources(),
            )
            .unwrap();

            let block = block_size.bytes();
            assert_eq!(u64::from(logical_block_size(&main).unwrap()), block);
            let starts: Vec<u64> = read_partitions(&main, block_size)
                .into_iter()
                .map(|(lba, _)| lba)
                .collect();
            let expected: Vec<u64> = [
                IMAGE_MARGIN,
                IMAGE_MARGIN + ESP_PARTITION_SIZE,
                IMAGE_MARGIN + ESP_PARTITION_SIZE + ROOT_PARTITION_SIZE,
            ]
            .iter()
            .map(|offset| offset / block)
            .collect();
            assert_eq!(starts, expected, "{block}-byte blocks");
            for lba in &starts
            {
                assert_eq!(u64::from(bytes_per_sector(&main, lba * block)), block);
            }

            // The data volume is populated, and reads back, at this size.
            let slice = PartitionSlice::new(
                File::options().read(true).write(true).open(&main).unwrap(),
                starts[2] * block,
                DATA_PARTITION_SIZE,
            )
            .unwrap();
            let fat = fatfs::FileSystem::new(slice, fatfs::FsOptions::new()).unwrap();
            let mut text = String::new();
            fat.root_dir()
                .open_file("test.txt")
                .unwrap()
                .read_to_string(&mut text)
                .unwrap();
            assert_eq!(text, "seraph");
        }
    }

    #[test]
    fn split_layout_puts_the_data_partition_alone_on_the_second_image()
    {
        let scratch = Scratch::new("split");
        let main = scratch.0.join("disk.img");
        let data_image = scratch.0.join("disk-data.img");
        let layout = DiskLayout {
            block_size: BlockSize::B4096,
            data: DataPlacement::SecondImage,
        };
        author_images(
            &main,
            &data_image,
            Arch::Riscv64,
            layout,
            &scratch.sources(),
        )
        .unwrap();

        let types = |path: &Path| -> Vec<uuid::Uuid> {
            read_partitions(path, BlockSize::B4096)
                .into_iter()
                .map(|(_, guid)| guid)
                .collect()
        };
        assert_eq!(
            types(&main),
            [
                gpt::partition_types::EFI.guid,
                seraph_root_type(Arch::Riscv64).guid
            ]
        );
        assert_eq!(types(&data_image), [seraph_data_type().guid]);
        assert_eq!(logical_block_size(&data_image).unwrap(), 4096);
    }

    #[test]
    fn authoring_with_data_on_the_main_image_removes_a_stale_data_image()
    {
        let scratch = Scratch::new("stale");
        let main = scratch.0.join("disk.img");
        let data_image = scratch.0.join("disk-data.img");
        fs::write(&data_image, b"stale").unwrap();
        author_images(
            &main,
            &data_image,
            Arch::X86_64,
            DiskLayout::default(),
            &scratch.sources(),
        )
        .unwrap();
        assert!(!data_image.exists());
    }

    #[test]
    fn gpt_block_size_finds_the_header_at_lba_1_of_either_size()
    {
        let mut head = vec![0u8; 4096 + GPT_SIGNATURE.len()];
        assert_eq!(gpt_block_size(&head), None);
        head[4096..].copy_from_slice(GPT_SIGNATURE);
        assert_eq!(gpt_block_size(&head), Some(4096));
        head[512..520].copy_from_slice(GPT_SIGNATURE);
        assert_eq!(gpt_block_size(&head), Some(512));
        // A file too short to hold a 4Kn LBA 1 is not taken for one.
        assert_eq!(gpt_block_size(&head[..4100]), Some(512));
        assert_eq!(gpt_block_size(&[0u8; 600]), None);
    }
}
