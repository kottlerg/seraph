// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/disk.rs

//! Build GPT disk images from sysroot contents. The images hold three FAT
//! partitions, an EFI System Partition (from sysroot/esp/), a Seraph root
//! partition (from sysroot/), and a Seraph data partition (from
//! sysroot/data/) that vfsd auto-mounts at /data, and a raw Seraph swap
//! partition. `disk.img` carries all four, or all but the data partition,
//! which then sits alone on a second image; the logical block size, 512 or
//! 4096 bytes, is chosen per authoring. Every pack signs the sysroot for the
//! harness whose bundle it composes ([`crate::signing::sign_sysroot`]), then
//! composes the ESP from the installed files ([`crate::esp::compose`]), then
//! writes the images, then checks what it wrote ([`crate::image_check`]). The
//! refusal boots of the `signing` case pack through
//! [`create_disk_image_substituting`], which writes bytes the harness staged
//! in place of named sysroot files and leaves the sysroot as it was.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{Context, Result, err};
use boot_protocol::role_guids;

use crate::arch::Arch;
use crate::bundle::Harness;
use crate::context::Context as BuildContext;
use crate::fat;
use crate::gpt::{self, Guid, guid};
use crate::signing::sign_for_harness;
use crate::util::step;

/// ESP partition size. Holds the kernel, the boot bundle (init + modules),
/// and the bootloader EFI. 64 MiB covers these with headroom for `--debug`
/// debuginfo and future bundle modules.
const ESP_PARTITION_SIZE: u64 = 64 * 1024 * 1024;

/// Root partition size. Holds every installed userspace binary under
/// `/services/` and `/programs/` plus the test binaries under `/tests/`. With
/// debuginfo off by default the tree is ~10 MiB; 192 MiB covers a full
/// `--debug` rebuild and ample future components.
const ROOT_PARTITION_SIZE: u64 = 192 * 1024 * 1024;

/// Data partition size. Backs the `/data` mountpoint (namespace-marker
/// fixture plus svctest scratch space); 256 MiB leaves generous headroom
/// for the test phases' scratch writes.
const DATA_PARTITION_SIZE: u64 = 256 * 1024 * 1024;

/// Swap partition size. A raw partition, neither formatted nor populated,
/// which vfsd hands to the swap service; 64 MiB holds the pages a small
/// `--mem` boot spills under pressure. The image file is sized with
/// `set_len`, so the partition costs no host disk until it is written.
const SWAP_PARTITION_SIZE: u64 = 64 * 1024 * 1024;

/// Bytes before the first partition and after the last: the first partition
/// starts 1 MiB in (standard GPT alignment, past the primary header and
/// entry array at either block size), and the last 1 MiB holds the backup
/// entry array and header.
const IMAGE_MARGIN: u64 = 1024 * 1024;

/// The GPT header signature, at the start of LBA 1.
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";

crate::argparse::value_enum! {
    /// Logical block size of an authored image: the unit of its GPT LBAs and the
    /// sector size of each of its FAT volumes. A launch presents the disk device
    /// at the same size ([`logical_block_size`] reads it back from the image).
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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
    /// `disk.img` carries all four partitions — the default.
    #[default]
    MainImage,
    /// `disk.img` carries the ESP and root; `disk-data.img` carries the data
    /// and swap partitions, for a boot that attaches it as a second disk, and
    /// the root partition the storage statement that names them
    /// ([`STATEMENT`]).
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

impl DiskLayout
{
    /// The image a boot of this layout attaches as its second disk:
    /// `disk-data.img` when the layout puts the data partition there, so the
    /// boot has its `/data`.
    #[must_use]
    pub fn second_image(self, ctx: &BuildContext) -> Option<PathBuf>
    {
        (self.data == DataPlacement::SecondImage).then(|| ctx.data_disk_image())
    }
}

/// One partition of an image: its GPT name, type and unique GUIDs, size, and
/// what it holds.
struct Volume
{
    name: &'static str,
    type_guid: Guid,
    unique_guid: Guid,
    bytes: u64,
    /// The entry's attribute bits ([`gpt::Partition::attributes`]).
    attributes: u64,
    contents: Contents,
}

/// What an authored partition holds.
enum Contents
{
    /// A FAT volume ([`crate::fat`]).
    Fat(FatSource),
    /// No filesystem: the partition's bytes are left as the new image's
    /// zeros.
    Raw,
}

/// The tree a FAT volume holds: a host directory's, or nothing when the
/// directory is absent, with each substitute's file in place of the one at its
/// path.
struct FatSource
{
    dir: PathBuf,
    /// Paths relative to `dir`.
    substitutes: Vec<Substitute>,
    /// Files and directories under `dir` the volume leaves out, as paths
    /// relative to `dir`.
    omit: Vec<PathBuf>,
}

/// A file a pack writes in place of the one the sysroot holds
/// ([`create_disk_image_substituting`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Substitute
{
    /// The file's path relative to the sysroot: under `esp/` on the ESP,
    /// under `data/` on the data partition, and on the root partition
    /// otherwise. The sysroot holds a file there.
    pub path: PathBuf,
    /// The host file whose bytes the partition holds in its place.
    pub source: PathBuf,
}

/// The host directories the three partitions are populated from, and the
/// files written in place of theirs.
struct Sources
{
    esp: PathBuf,
    root: PathBuf,
    data: PathBuf,
    /// Paths relative to the sysroot.
    substitutes: Vec<Substitute>,
    /// Files and directories the root partition leaves out, as paths relative
    /// to the sysroot.
    omit_from_root: Vec<PathBuf>,
}

/// Create the GPT disk image at `<project_root>/disk.img`, and, when the
/// layout places the data partition on a second image, `disk-data.img`
/// beside it.
///
/// The images hold three FAT partitions and a raw one:
/// - ESP ([`ESP_PARTITION_SIZE`]): populated from `sysroot/esp/`
/// - ROOT ([`ROOT_PARTITION_SIZE`]): populated from `sysroot/`
///   excluding `esp/` and `data/`
/// - DATA ([`DATA_PARTITION_SIZE`]): populated from `sysroot/data/`
/// - SWAP ([`SWAP_PARTITION_SIZE`]): raw, left zero
///
/// `disk.img` carries the ESP and ROOT, and DATA and SWAP too unless
/// `layout.data` is [`DataPlacement::SecondImage`], which puts DATA and SWAP on
/// `disk-data.img`, in that order, and stages the storage statement naming
/// them on ROOT ([`stage_statement`]): vfsd gives a disk other than the boot
/// disk a role only where the statement names its partition (docs/storage.md
/// § GPT Role-GUID Discovery). Authoring with DATA on `disk.img` removes a
/// `disk-data.img` an earlier
/// authoring left, so a stale second copy of the data partition cannot be
/// attached. Every image's GPT LBAs and FAT sectors are `layout.block_size`
/// bytes.
///
/// The ESP is composed first, for the harness `sysroot/.harness` records
/// (`crate::sysroot::recorded_harness`), as [`create_disk_image_for`] says.
///
/// ROOT's GPT type-GUID is the arch-specific Seraph root GUID, DATA's the
/// arch-neutral Seraph data GUID, and SWAP's the arch-neutral Seraph swap
/// GUID (see [`boot_protocol::role_guids`]) so vfsd can identify each by
/// role on the boot disk, and the statement can name DATA and SWAP on
/// `disk-data.img` by their unique GUIDs. vfsd auto-mounts the data
/// partition at `/data`. The data tree is placed only on the data partition, not
/// duplicated onto root; vfsd's fall-through still serves `/data` from
/// root on images that choose to carry it there instead.
pub fn create_disk_image(ctx: &BuildContext, arch: Arch, layout: DiskLayout) -> Result<()>
{
    let harness = crate::sysroot::recorded_harness(ctx)?;
    pack(ctx, arch, layout, harness, Vec::new())
}

/// [`create_disk_image`], composing the bundle of `harness` rather than the
/// recorded one: sign the sysroot for `harness`
/// ([`crate::signing::sign_for_harness`]), compose the ESP from the installed
/// files ([`crate::esp::compose`]), and write the images. A test that boots
/// another harness's bundle packs with it, and packs again with
/// [`create_disk_image`] to restore the recorded one.
///
/// # Errors
/// Fails as [`create_disk_image`] does.
pub fn create_disk_image_for(
    ctx: &BuildContext,
    arch: Arch,
    layout: DiskLayout,
    harness: Harness,
) -> Result<()>
{
    pack(ctx, arch, layout, harness, Vec::new())
}

/// [`create_disk_image_for`], with each of `substitutes` written in place of the
/// sysroot file at its path. The sysroot is signed and left as every pack
/// leaves it; only the images carry the substitutes, as written, so a test can
/// boot an object no pack would sign (a tampered or foreign-signed image)
/// without changing the sysroot a later pack signs.
///
/// # Errors
/// Fails as [`create_disk_image`] does; when a substitute's path is not a
/// relative path naming a file the sysroot holds, or its source cannot be
/// read.
pub fn create_disk_image_substituting(
    ctx: &BuildContext,
    arch: Arch,
    layout: DiskLayout,
    harness: Harness,
    substitutes: &[Substitute],
) -> Result<()>
{
    pack(ctx, arch, layout, harness, substitutes.to_vec())
}

/// The pack of [`create_disk_image`], [`create_disk_image_for`] and
/// [`create_disk_image_substituting`].
fn pack(
    ctx: &BuildContext,
    arch: Arch,
    layout: DiskLayout,
    harness: Harness,
    substitutes: Vec<Substitute>,
) -> Result<()>
{
    let image_path = ctx.disk_image();
    step(&format!(
        "Creating disk image: {} ({}-byte blocks)",
        image_path.display(),
        layout.block_size.bytes()
    ));

    stage_statement(&ctx.sysroot, layout.data)?;
    // Every pack signs what it packs, so no path writes an unsigned image,
    // and composes the ESP from what it signed, so the ESP of every image is
    // copies of the installed files: `build`, `mkdisk` and every harness that
    // repacks. ktest is signed `init` only in an image whose bundle boots it.
    sign_for_harness(ctx, arch, harness)?;
    crate::esp::compose(ctx, arch, harness)?;

    // A sysroot staged for a services-layer harness packs a services-layer
    // image, which holds no file of the programs layer; deciding it here, from
    // the staged recipes, keeps a later `--repack-only` (the storage cells'
    // `--split-data`) to the composition the staging chose.
    let omit_from_root = if crate::svctest_stage::services_layer(&ctx.sysroot)
    {
        step("Services-layer image: the programs layer is left out");
        crate::svctest_stage::PROGRAMS_LAYER
            .iter()
            .map(PathBuf::from)
            .collect()
    }
    else
    {
        Vec::new()
    };
    let sources = Sources {
        esp: ctx.sysroot_esp(),
        root: ctx.sysroot.clone(),
        data: ctx.sysroot.join("data"),
        substitutes,
        omit_from_root,
    };
    let data_image = ctx.data_disk_image();
    author_images(&image_path, &data_image, arch, layout, &sources)?;
    if layout.data == DataPlacement::SecondImage
    {
        step(&format!("Data partition image: {}", data_image.display()));
    }
    // An independent reader checks every image a pack writes, so none exists
    // unchecked; a substitute is a deliberate difference from the installed
    // files, so such an image's ESP is not held to them.
    let esp = if sources.substitutes.is_empty()
    {
        crate::image_check::EspCheck::Copies
    }
    else
    {
        crate::image_check::EspCheck::Skipped
    };
    crate::image_check::check(
        &image_path,
        (layout.data == DataPlacement::SecondImage).then_some(data_image.as_path()),
        esp,
        &ctx.target_dir.join("xtask").join("image-check"),
    )?;

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
    let [on_esp, on_root, on_data] = split_substitutes(&sources.substitutes)?;
    let fat = |dir: &Path, substitutes, omit| {
        Contents::Fat(FatSource {
            dir: dir.to_path_buf(),
            substitutes,
            omit,
        })
    };
    let esp = Volume {
        name: "ESP",
        type_guid: gpt::EFI_SYSTEM_PARTITION,
        unique_guid: ESP_UNIQUE_GUID,
        bytes: ESP_PARTITION_SIZE,
        attributes: 0,
        contents: fat(&sources.esp, on_esp, Vec::new()),
    };
    let root = Volume {
        name: "ROOT",
        type_guid: seraph_root_type(arch),
        unique_guid: ROOT_UNIQUE_GUID,
        bytes: ROOT_PARTITION_SIZE,
        attributes: 0,
        contents: fat(&sources.root, on_root, sources.omit_from_root.clone()),
    };
    // The data tree is not also written to the root partition
    // (populate_dir skips top-level data/).
    let data = Volume {
        name: "DATA",
        type_guid: role_guids::SERAPH_DATA,
        unique_guid: DATA_UNIQUE_GUID,
        bytes: DATA_PARTITION_SIZE,
        attributes: 0,
        contents: fat(&sources.data, on_data, Vec::new()),
    };
    let swap = Volume {
        name: "SWAP",
        type_guid: role_guids::SERAPH_SWAP,
        unique_guid: SWAP_UNIQUE_GUID,
        bytes: SWAP_PARTITION_SIZE,
        attributes: 0,
        contents: Contents::Raw,
    };

    match layout.data
    {
        DataPlacement::MainImage =>
        {
            write_image(
                main_image,
                layout.block_size,
                MAIN_DISK_GUID,
                &[esp, root, data, swap],
            )?;
            if data_image.exists()
            {
                fs::remove_file(data_image)
                    .with_context(|| format!("failed to remove stale {}", data_image.display()))?;
            }
        }
        DataPlacement::SecondImage =>
        {
            write_image(main_image, layout.block_size, MAIN_DISK_GUID, &[esp, root])?;
            write_image(data_image, layout.block_size, DATA_DISK_GUID, &[data, swap])?;
        }
    }
    Ok(())
}

/// The unique GUIDs of a foreign disk's ESP, ROOT, DATA and SWAP
/// ([`create_foreign_image`]): none is a partition of `disk.img` or
/// `disk-data.img`.
const FOREIGN_UNIQUE_GUIDS: [Guid; 4] = [
    guid(0xf0e1_0001, 0x5eed, 0x4bad, [0x8a, 0x11, 0, 0, 0, 0, 0, 1]),
    guid(0xf0e1_0002, 0x5eed, 0x4bad, [0x8a, 0x11, 0, 0, 0, 0, 0, 2]),
    guid(0xf0e1_0003, 0x5eed, 0x4bad, [0x8a, 0x11, 0, 0, 0, 0, 0, 3]),
    guid(0xf0e1_0004, 0x5eed, 0x4bad, [0x8a, 0x11, 0, 0, 0, 0, 0, 4]),
];

/// The disk GUID of a foreign disk ([`create_foreign_image`]).
const FOREIGN_DISK_GUID: Guid = guid(0xf0e1_0000, 0x5eed, 0x4bad, [0x8a, 0x11, 0, 0, 0, 0, 0, 0]);

/// Author at `path` a foreign disk, as an attacker's or a stray disk
/// attached beside the boot disk carries: an ESP, a ROOT of `arch`, a DATA
/// and a SWAP, of `disk.img`'s sizes and so at its LBAs, each with the
/// partition priority `priority` (attribute bits 48-63) and a unique GUID
/// of its own ([`FOREIGN_UNIQUE_GUIDS`]), and no filesystem. vfsd must give
/// none of them a role: the disk is not the boot disk, and the storage
/// statement names none of its partitions.
///
/// # Errors
/// Fails when the image cannot be written.
pub fn create_foreign_image(
    path: &Path,
    arch: Arch,
    block_size: BlockSize,
    priority: u16,
) -> Result<()>
{
    let attributes = u64::from(priority) << 48;
    let [esp, root, data, swap] = FOREIGN_UNIQUE_GUIDS;
    let volume = |name, type_guid, unique_guid, bytes| Volume {
        name,
        type_guid,
        unique_guid,
        bytes,
        attributes,
        contents: Contents::Raw,
    };
    write_image(
        path,
        block_size,
        FOREIGN_DISK_GUID,
        &[
            volume("ESP", gpt::EFI_SYSTEM_PARTITION, esp, ESP_PARTITION_SIZE),
            volume("ROOT", seraph_root_type(arch), root, ROOT_PARTITION_SIZE),
            volume("DATA", role_guids::SERAPH_DATA, data, DATA_PARTITION_SIZE),
            volume("SWAP", role_guids::SERAPH_SWAP, swap, SWAP_PARTITION_SIZE),
        ],
    )
}

/// The storage statement the split layout stages, at
/// `storage_statement::PATH` on the root partition: the data partition at
/// `/data` and the swap partition, each by its unique GUID, both on
/// `disk-data.img`.
pub static STATEMENT: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    let mut statement = storage_statement::Statement::new();
    let named = [
        storage_statement::Named::new(
            storage_statement::Role::Data,
            Some("/data"),
            DATA_UNIQUE_GUID,
        ),
        storage_statement::Named::new(storage_statement::Role::Swap, None, SWAP_UNIQUE_GUID),
    ];
    // Two distinct GUIDs, one data path and one swap: the parser's grammar
    // takes both (the statement_parses test).
    for entry in named.into_iter().flatten()
    {
        let _ = statement.push(entry);
    }
    statement.render()
});

/// Stage the storage statement in `sysroot` for a pack whose data
/// placement is `data`: [`STATEMENT`] at `storage_statement::PATH` for
/// [`DataPlacement::SecondImage`], which the pack then signs
/// (`crate::signing::sign_sysroot`); for [`DataPlacement::MainImage`], a
/// statement there whose bytes are [`STATEMENT`]'s is removed, since its
/// partitions are on `disk.img`, and any other statement is the deployer's
/// and is left. Fails when the staged text is one vfsd's parser refuses.
fn stage_statement(sysroot: &Path, data: DataPlacement) -> Result<()>
{
    let path = sysroot.join(storage_statement::PATH.trim_start_matches('/'));
    match data
    {
        DataPlacement::SecondImage =>
        {
            storage_statement::parse(STATEMENT.as_bytes())
                .map_err(|e| err!("the staged storage statement is refused: {e}"))?;
            if let Some(dir) = path.parent()
            {
                fs::create_dir_all(dir)
                    .with_context(|| format!("failed to create {}", dir.display()))?;
            }
            // A statement already staged keeps its signature when its body
            // is the one staged.
            if !holds_statement(&path)
            {
                fs::write(&path, STATEMENT.as_bytes())
                    .with_context(|| format!("failed to write {}", path.display()))?;
            }
        }
        DataPlacement::MainImage =>
        {
            if holds_statement(&path)
            {
                fs::remove_file(&path)
                    .with_context(|| format!("failed to remove {}", path.display()))?;
            }
        }
    }
    Ok(())
}

/// Whether the file at `path` is [`STATEMENT`], signed or not
/// (`crate::signing::body_of`).
fn holds_statement(path: &Path) -> bool
{
    fs::read(path).is_ok_and(|bytes| {
        crate::signing::body_of(&bytes).is_ok_and(|body| body == STATEMENT.as_bytes())
    })
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

/// Write a zero-filled image at `path` whose GPT carries `disk_guid` and holds
/// `volumes` as partitions 1, 2, … in order, each [`Contents::Fat`] one a
/// FAT volume holding its source's tree, and each [`Contents::Raw`] one left
/// zero.
fn write_image(
    path: &Path,
    block_size: BlockSize,
    disk_guid: Guid,
    volumes: &[Volume],
) -> Result<()>
{
    let (starts, image_size) = plan(volumes, block_size)?;
    {
        let f = File::create(path)
            .with_context(|| format!("failed to create disk image {}", path.display()))?;
        f.set_len(image_size).context("failed to set image size")?;
    }

    write_gpt(path, block_size, image_size, disk_guid, volumes, &starts)?;

    for (volume, start_lba) in volumes.iter().zip(&starts)
    {
        let Contents::Fat(source) = &volume.contents
        else
        {
            continue;
        };
        write_fat_partition(
            path,
            start_lba
                .checked_mul(block_size.bytes())
                .context("partition offset exceeds u64")?,
            volume.bytes,
            block_size,
            &volume.unique_guid,
            source,
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

/// The layout the sysroot's disk images have now: `disk.img`'s block size,
/// and the data partition on `disk-data.img` when that image is there. A
/// command that stages a file for one boot and restores it afterwards repacks
/// in this layout both times, so a 4Kn or split image stays one.
///
/// # Errors
/// Fails as [`image_layout`] does.
pub fn current_layout(ctx: &BuildContext) -> Result<DiskLayout>
{
    image_layout(&ctx.disk_image(), &ctx.data_disk_image())
}

/// The layout of the images at `main_image` and `data_image`, as
/// [`current_layout`] reads it.
///
/// # Errors
/// Fails when `main_image` carries no GPT header at either block size.
fn image_layout(main_image: &Path, data_image: &Path) -> Result<DiskLayout>
{
    let block_size = match logical_block_size(main_image)?
    {
        512 => BlockSize::B512,
        4096 => BlockSize::B4096,
        other => crate::error::bail!(
            "{} has {other}-byte blocks, which mkdisk does not author",
            main_image.display()
        ),
    };
    let data = if data_image.is_file()
    {
        DataPlacement::SecondImage
    }
    else
    {
        DataPlacement::MainImage
    };
    Ok(DiskLayout { block_size, data })
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
const ESP_UNIQUE_GUID: Guid = guid(
    0xa1b2_c3d4,
    0xe5f6,
    0x7890,
    [0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89],
);
const ROOT_UNIQUE_GUID: Guid = guid(
    0x1234_5678,
    0xabcd,
    0xef01,
    [0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01],
);
const DATA_UNIQUE_GUID: Guid = guid(
    0xc0ff_ee01,
    0x2345,
    0x6789,
    [0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89],
);
const SWAP_UNIQUE_GUID: Guid = guid(
    0x5a9f_0e11,
    0x2345,
    0x6789,
    [0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89],
);

/// The disk GUID of `disk.img`, `2aa7259c-97a5-4327-9347-ceaf2a23a3b6`: fixed, like
/// the partition GUIDs above, so two authorings of one layout carry the same
/// table.
const MAIN_DISK_GUID: Guid = guid(
    0x2aa7_259c,
    0x97a5,
    0x4327,
    [0x93, 0x47, 0xce, 0xaf, 0x2a, 0x23, 0xa3, 0xb6],
);

/// The disk GUID of `disk-data.img`, `369f2a4d-cb86-4700-a14d-0798cff8dd38`:
/// distinct from [`MAIN_DISK_GUID`], since a split boot attaches both images.
const DATA_DISK_GUID: Guid = guid(
    0x369f_2a4d,
    0xcb86,
    0x4700,
    [0xa1, 0x4d, 0x07, 0x98, 0xcf, 0xf8, 0xdd, 0x38],
);

/// The Seraph root partition type GUID for `arch`.
fn seraph_root_type(arch: Arch) -> Guid
{
    match arch
    {
        Arch::X86_64 => role_guids::SERAPH_ROOT_X86_64,
        Arch::Riscv64 => role_guids::SERAPH_ROOT_RISCV64,
    }
}

/// Write the protective MBR and a GPT carrying `disk_guid` and holding
/// `volumes` as partitions 1, 2, … at `starts`, with their deterministic unique
/// GUIDs, into the image at `image_path`.
fn write_gpt(
    image_path: &Path,
    block_size: BlockSize,
    image_size: u64,
    disk_guid: Guid,
    volumes: &[Volume],
    starts: &[u64],
) -> Result<()>
{
    let partitions: Vec<gpt::Partition<'_>> = volumes
        .iter()
        .zip(starts)
        .map(|(volume, &first_lba)| gpt::Partition {
            name: volume.name,
            type_guid: volume.type_guid,
            unique_guid: volume.unique_guid,
            first_lba,
            blocks: block_size.blocks(volume.bytes),
            attributes: volume.attributes,
        })
        .collect();
    let regions = gpt::encode(&gpt::Table {
        block_size: block_size.bytes(),
        total_blocks: block_size.blocks(image_size),
        disk_guid,
        partitions: &partitions,
    })
    .with_context(|| format!("failed to lay out the GPT of {}", image_path.display()))?;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(image_path)
        .context("failed to open image for GPT")?;
    for region in regions
    {
        file.seek(SeekFrom::Start(region.offset))
            .and_then(|_| file.write_all(&region.bytes))
            .with_context(|| format!("failed to write the GPT of {}", image_path.display()))?;
    }
    file.sync_all().context("failed to sync GPT")?;

    Ok(())
}

/// Write the FAT volume of the `bytes`-byte partition at byte `offset` of the image at
/// `image_path`, its sectors `block_size` bytes and its serial number the first four bytes of
/// `unique_guid`, holding the tree under `source.dir` ([`host_tree`]), or nothing when that
/// directory is absent, with each of `source.substitutes` in place of the file at its path
/// ([`substitute`]). The partition's bytes are the new image's zeros, as
/// [`fat::write_volume`] requires.
fn write_fat_partition(
    image_path: &Path,
    offset: u64,
    bytes: u64,
    block_size: BlockSize,
    unique_guid: &Guid,
    source: &FatSource,
) -> Result<()>
{
    let source_dir = source.dir.as_path();
    let mut tree = if source_dir.exists()
    {
        host_tree(source_dir, source_dir, &source.omit)?
    }
    else
    {
        Vec::new()
    };
    for each in &source.substitutes
    {
        substitute(&mut tree, &each.path, &each.source).with_context(|| {
            format!(
                "substituting {} for {} of {}",
                each.source.display(),
                each.path.display(),
                source_dir.display()
            )
        })?;
    }
    let [a, b, c, d, ..] = *unique_guid;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(image_path)
        .with_context(|| {
            format!(
                "failed to open {} for its FAT volumes",
                image_path.display()
            )
        })?;
    fat::write_volume(
        &mut file,
        offset,
        bytes,
        block_size.fat_sector(),
        u32::from_le_bytes([a, b, c, d]),
        &tree,
    )
    .with_context(|| {
        format!(
            "failed to write the FAT volume from {}",
            source_dir.display()
        )
    })?;
    file.sync_all().context("failed to sync the FAT volume")
}

/// `substitutes`, whose paths are relative to the sysroot, split by the volume each lands
/// on, `[ESP, root, data]`, each path made relative to its volume's directory: the ESP's
/// under `esp/`, the data partition's under `data/`, and the root partition's every
/// other.
///
/// # Errors
/// When a path is not relative, or holds a component other than a name.
fn split_substitutes(substitutes: &[Substitute]) -> Result<[Vec<Substitute>; 3]>
{
    let mut volumes: [Vec<Substitute>; 3] = Default::default();
    for each in substitutes
    {
        let mut names = Vec::new();
        for component in each.path.components()
        {
            let std::path::Component::Normal(name) = component
            else
            {
                crate::error::bail!(
                    "the substitute path {} is not a path of names relative to the sysroot",
                    each.path.display()
                );
            };
            names.push(name);
        }
        let (volume, within) = match names.split_first()
        {
            Some((first, rest)) if *first == "esp" => (0, rest),
            Some((first, rest)) if *first == "data" => (2, rest),
            _ => (1, names.as_slice()),
        };
        if let Some(list) = volumes.get_mut(volume)
        {
            list.push(Substitute {
                path: within.iter().collect(),
                source: each.source.clone(),
            });
        }
    }
    Ok(volumes)
}

/// Put the host file `source` in place of the file at `path`, relative to the volume's
/// root, in `tree`.
///
/// # Errors
/// When `tree` holds no file at `path`, or the length of `source` cannot be read.
fn substitute(tree: &mut [fat::Entry], path: &Path, source: &Path) -> Result<()>
{
    let mut level = tree;
    let mut names = path.components().peekable();
    while let Some(component) = names.next()
    {
        let entries = std::mem::take(&mut level);
        let Some(entry) = entries
            .iter_mut()
            .find(|entry| component.as_os_str() == entry.name.as_str())
        else
        {
            break;
        };
        let last = names.peek().is_none();
        match &mut entry.kind
        {
            fat::Kind::Dir(children) if !last => level = children.as_mut_slice(),
            fat::Kind::File { path: file, len } if last =>
            {
                *len = fs::metadata(source)
                    .with_context(|| format!("failed to read the size of {}", source.display()))?
                    .len();
                source.clone_into(file);
                return Ok(());
            }
            fat::Kind::Dir(_) | fat::Kind::File { .. } => break,
        }
    }
    crate::error::bail!("the volume holds no file at {}", path.display())
}

/// The files and directories under `host_dir`, in name order, as a FAT volume holds them.
///
/// Skips build metadata (`.arch`, `.harness`, `NvVars`), the `esp` directory, and
/// at the top of `sysroot_root` the `data` directory: `esp` and `data` are mount
/// points with their own partitions, and so not root content. Entries other than files and directories are skipped,
/// and so is each file or directory whose path relative to `sysroot_root` `omit` names.
///
/// # Errors
/// Fails when a directory cannot be read or a name is not UTF-8.
fn host_tree(host_dir: &Path, sysroot_root: &Path, omit: &[PathBuf]) -> Result<Vec<fat::Entry>>
{
    let mut entries: Vec<_> = fs::read_dir(host_dir)
        .with_context(|| format!("failed to read {}", host_dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to read {}", host_dir.display()))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);

    let mut tree = Vec::with_capacity(entries.len());
    for entry in entries
    {
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| crate::error::err!("{} has a name that is not UTF-8", path.display()))?;

        // Skip build metadata and the ESP mount point (populated separately).
        if name == ".arch" || name == ".harness" || name == "NvVars" || name == "esp"
        {
            continue;
        }

        // `data` is a mount point with its own SERAPH_DATA partition, so it
        // is excluded from the root partition (symmetric with `esp`). Skip
        // it only at the sysroot top level — a nested `data/` elsewhere in
        // the tree is still copied.
        if name == "data" && host_dir == sysroot_root
        {
            continue;
        }

        if path
            .strip_prefix(sysroot_root)
            .is_ok_and(|relative| omit.iter().any(|o| o == relative))
        {
            continue;
        }

        let ft = entry
            .file_type()
            .with_context(|| format!("failed to get file type: {}", path.display()))?;
        let kind = if ft.is_dir()
        {
            fat::Kind::Dir(host_tree(&path, sysroot_root, omit)?)
        }
        else if ft.is_file()
        {
            let len = entry
                .metadata()
                .with_context(|| format!("failed to read the size of {}", path.display()))?
                .len();
            fat::Kind::File { path, len }
        }
        else
        {
            continue;
        };
        tree.push(fat::Entry { name, kind });
    }
    Ok(tree)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

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
                substitutes: Vec::new(),
                omit_from_root: Vec::new(),
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

    /// The `len` bytes of `path` at `offset`.
    fn read_range(path: &Path, offset: u64, len: u64) -> Vec<u8>
    {
        let mut file = File::open(path).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut bytes = vec![0u8; usize::try_from(len).unwrap()];
        file.read_exact(&mut bytes).unwrap();
        bytes
    }

    /// `(first_lba, type GUID)` of each partition, in partition order, read
    /// back through vfsd's GPT parser at `block_size`.
    fn read_partitions(path: &Path, block_size: BlockSize) -> Vec<(u64, Guid)>
    {
        let size = block_size.bytes();
        let Ok(header) = vfsd_gpt::parse_header(&read_range(path, size, size), 1)
        else
        {
            panic!("vfsd-gpt refused the GPT header of {}", path.display());
        };
        let scan = vfsd_gpt::collect_partitions(&header, |lba, buf| {
            buf.copy_from_slice(&read_range(path, lba * size, size));
            true
        });
        assert_eq!(scan.stop, None);
        scan.entries
            .iter()
            .map(|e| (e.first_lba, e.type_guid))
            .collect()
    }

    /// The disk GUID of the GPT header at LBA 1 of `path`.
    fn disk_guid(path: &Path, block_size: BlockSize) -> Vec<u8>
    {
        read_range(path, block_size.bytes() + 56, 16)
    }

    /// Whether the `len` bytes of `path` at `offset` are all zero.
    fn block_is_zero(path: &Path, offset: u64, len: u64) -> bool
    {
        let mut file = File::open(path).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut bytes = vec![0u8; usize::try_from(len).unwrap()];
        file.read_exact(&mut bytes).unwrap();
        bytes.iter().all(|&b| b == 0)
    }

    #[test]
    fn the_main_image_carries_each_role_in_partition_order()
    {
        let scratch = Scratch::new("roles");
        let main = scratch.0.join("disk.img");
        author_images(
            &main,
            &scratch.0.join("disk-data.img"),
            Arch::X86_64,
            DiskLayout::default(),
            &scratch.sources(),
        )
        .unwrap();
        let types: Vec<Guid> = read_partitions(&main, BlockSize::B512)
            .into_iter()
            .map(|(_, guid)| guid)
            .collect();
        assert_eq!(
            types,
            [
                gpt::EFI_SYSTEM_PARTITION,
                role_guids::SERAPH_ROOT_X86_64,
                role_guids::SERAPH_DATA,
                role_guids::SERAPH_SWAP
            ]
        );
    }

    /// Whether the files at `a` and `b` hold the same bytes.
    fn same_bytes(first: &Path, second: &Path) -> bool
    {
        let mut files = [File::open(first).unwrap(), File::open(second).unwrap()];
        let mut bufs = [vec![0u8; 1 << 20], vec![0u8; 1 << 20]];
        loop
        {
            let [one, two] = &mut files;
            let [ours, theirs] = &mut bufs;
            let len = one.read(ours).unwrap();
            if len == 0
            {
                return two.read(theirs).unwrap() == 0;
            }
            if two.read_exact(&mut theirs[..len]).is_err() || ours[..len] != theirs[..len]
            {
                return false;
            }
        }
    }

    // Defect caught: each authoring drew the GPT's disk GUID at random, and the FAT writer
    // stamped each entry with the host's clock, so two builds of one image differed.
    #[test]
    fn two_authorings_of_a_layout_write_identical_images()
    {
        for data in [DataPlacement::MainImage, DataPlacement::SecondImage]
        {
            let layout = DiskLayout {
                block_size: BlockSize::B512,
                data,
            };
            let author = |run: &str| -> Scratch {
                let scratch = Scratch::new(&format!("again-{run}-{data:?}"));
                author_images(
                    &scratch.0.join("disk.img"),
                    &scratch.0.join("disk-data.img"),
                    Arch::X86_64,
                    layout,
                    &scratch.sources(),
                )
                .unwrap();
                scratch
            };
            let (first, second) = (author("a"), author("b"));
            for image in ["disk.img", "disk-data.img"]
            {
                let (a, b) = (first.0.join(image), second.0.join(image));
                assert_eq!(a.is_file(), b.is_file());
                assert!(!a.is_file() || same_bytes(&a, &b), "{image}, {data:?}");
            }
        }
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
                IMAGE_MARGIN + ESP_PARTITION_SIZE + ROOT_PARTITION_SIZE + DATA_PARTITION_SIZE,
            ]
            .iter()
            .map(|offset| offset / block)
            .collect();
            assert_eq!(starts, expected, "{block}-byte blocks");
            for lba in &starts[..3]
            {
                assert_eq!(u64::from(bytes_per_sector(&main, lba * block)), block);
            }
            assert_eq!(
                fs::metadata(&main).unwrap().len(),
                IMAGE_MARGIN
                    + ESP_PARTITION_SIZE
                    + ROOT_PARTITION_SIZE
                    + DATA_PARTITION_SIZE
                    + SWAP_PARTITION_SIZE
                    + IMAGE_MARGIN
            );
            // The swap partition is raw: no FAT volume is written to it.
            assert!(
                block_is_zero(&main, starts[3] * block, block),
                "{block}-byte blocks"
            );

            // The data volume is populated, and reads back, at this size.
            let mut file = File::open(&main).unwrap();
            let tree = crate::fat_read::read_volume(
                &mut file,
                starts[2] * block,
                block_size.fat_sector().into(),
            )
            .unwrap();
            assert_eq!(
                tree.into_iter().collect::<Vec<_>>(),
                [(
                    "/test.txt".to_owned(),
                    crate::fat_read::Node::File(b"seraph".to_vec())
                )]
            );
        }
    }

    #[test]
    fn split_layout_puts_the_data_and_swap_partitions_on_the_second_image()
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

        let types = |path: &Path| -> Vec<Guid> {
            read_partitions(path, BlockSize::B4096)
                .into_iter()
                .map(|(_, guid)| guid)
                .collect()
        };
        assert_eq!(
            types(&main),
            [gpt::EFI_SYSTEM_PARTITION, role_guids::SERAPH_ROOT_RISCV64]
        );
        assert_eq!(
            types(&data_image),
            [role_guids::SERAPH_DATA, role_guids::SERAPH_SWAP]
        );
        assert_eq!(logical_block_size(&data_image).unwrap(), 4096);
        // A boot attaches both images, so each carries its own disk GUID.
        assert_ne!(
            disk_guid(&main, BlockSize::B4096),
            disk_guid(&data_image, BlockSize::B4096)
        );
    }

    // Defect caught: a split layout with no statement naming its second
    // image's partitions, so vfsd gives them no role and the boot has no
    // `/data` and no swap; a statement vfsd's parser refuses; or a single
    // image left with a statement naming partitions it carries, or with a
    // deployer's statement removed.
    #[test]
    fn the_split_layout_stages_the_statement_and_the_single_image_removes_it()
    {
        let scratch = Scratch::new("statement");
        let sysroot = scratch.0.join("sysroot");
        let path = sysroot.join(storage_statement::PATH.trim_start_matches('/'));
        stage_statement(&sysroot, DataPlacement::SecondImage).unwrap();
        let staged = fs::read(&path).unwrap();
        assert_eq!(staged, STATEMENT.as_bytes());
        let statement = storage_statement::parse(&staged).unwrap();
        assert_eq!(
            statement.named(storage_statement::Role::Data, Some(b"/data")),
            Some(DATA_UNIQUE_GUID)
        );
        assert_eq!(
            statement.named(storage_statement::Role::Swap, None),
            Some(SWAP_UNIQUE_GUID)
        );
        assert_eq!(statement.entries().len(), 2);
        stage_statement(&sysroot, DataPlacement::MainImage).unwrap();
        assert!(!path.exists());
        // A statement of other bytes is the deployer's: it stays.
        let own = b"swap 00000000-0000-0000-0000-000000000001\n";
        fs::write(&path, own).unwrap();
        stage_statement(&sysroot, DataPlacement::MainImage).unwrap();
        assert_eq!(fs::read(&path).unwrap(), own);
    }

    // Defect caught: a foreign disk whose partitions are not each role's at
    // the priority asked for, or that share a unique GUID with disk.img's, so
    // the storage-roles case tests another disk than it says.
    #[test]
    fn a_foreign_image_carries_every_role_at_its_priority_under_its_own_guids()
    {
        let scratch = Scratch::new("foreign");
        let main = scratch.0.join("disk.img");
        let foreign = scratch.0.join("foreign.img");
        author_images(
            &main,
            &scratch.0.join("disk-data.img"),
            Arch::X86_64,
            DiskLayout::default(),
            &scratch.sources(),
        )
        .unwrap();
        create_foreign_image(&foreign, Arch::X86_64, BlockSize::B512, 0xFFFF).unwrap();
        let entries = |path: &Path| {
            let size = BlockSize::B512.bytes();
            let header = vfsd_gpt::parse_header(&read_range(path, size, size), 1).unwrap();
            vfsd_gpt::collect_partitions(&header, |lba, buf| {
                buf.copy_from_slice(&read_range(path, lba * size, size));
                true
            })
            .entries
        };
        let (ours, theirs) = (entries(&main), entries(&foreign));
        assert_eq!(theirs.len(), ours.len());
        for (their, our) in theirs.iter().zip(&ours)
        {
            assert_eq!(their.type_guid, our.type_guid);
            assert_eq!(
                (their.first_lba, their.length_lba),
                (our.first_lba, our.length_lba)
            );
            assert_eq!(their.attributes >> 48, 0xFFFF);
            assert!(ours.iter().all(|o| o.uuid != their.uuid));
        }
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

    // Defect caught: the debug-port case restored a 4Kn or split image as a
    // 512-byte single image, deleting disk-data.img.
    #[test]
    fn the_layout_read_back_is_the_one_authored_and_survives_a_repack()
    {
        for block_size in [BlockSize::B512, BlockSize::B4096]
        {
            for data in [DataPlacement::MainImage, DataPlacement::SecondImage]
            {
                let layout = DiskLayout { block_size, data };
                let scratch = Scratch::new(&format!("layout-{}-{data:?}", block_size.bytes()));
                let main = scratch.0.join("disk.img");
                let data_image = scratch.0.join("disk-data.img");
                let sources = scratch.sources();
                author_images(&main, &data_image, Arch::X86_64, layout, &sources).unwrap();
                assert_eq!(image_layout(&main, &data_image).unwrap(), layout);

                // A repack in the layout read back keeps it.
                let read = image_layout(&main, &data_image).unwrap();
                author_images(&main, &data_image, Arch::X86_64, read, &sources).unwrap();
                assert_eq!(image_layout(&main, &data_image).unwrap(), layout);
                assert_eq!(data_image.is_file(), data == DataPlacement::SecondImage);
            }
        }
    }

    // Defect caught: a split layout booted without its data disk, so the
    // boot had no /data.
    #[test]
    fn only_a_split_layout_boots_a_second_image()
    {
        let ctx = BuildContext {
            root: PathBuf::from("/w"),
            sysroot: PathBuf::from("/w/sysroot"),
            target_dir: PathBuf::from("/w/target"),
        };
        for block_size in [BlockSize::B512, BlockSize::B4096]
        {
            let split = DiskLayout {
                block_size,
                data: DataPlacement::SecondImage,
            };
            assert_eq!(split.second_image(&ctx), Some(ctx.data_disk_image()));
            let single = DiskLayout {
                block_size,
                data: DataPlacement::MainImage,
            };
            assert_eq!(single.second_image(&ctx), None);
        }
    }

    // Defect caught: a substitute written to the wrong volume or path, the
    // sysroot's file packed in its place, or a substitute for a file the
    // sysroot does not hold packed as a new file, which would boot a layout no
    // build makes.
    #[test]
    fn a_substitute_replaces_the_named_file_on_its_volume_alone()
    {
        use crate::fat_read::{Node, read_volume};

        let scratch = Scratch::new("substitute");
        let sysroot = scratch.0.join("sysroot");
        let files = [
            ("esp/EFI/seraph/kernel", b"kernel".as_slice()),
            ("services/timed", b"timed"),
            ("services/drivers/timed", b"driver"),
            ("data/note", b"note"),
        ];
        for (path, bytes) in files
        {
            let full = sysroot.join(path);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(&full, bytes).unwrap();
        }
        let staged = |name: &str, bytes: &[u8]| {
            let path = scratch.0.join(name);
            fs::write(&path, bytes).unwrap();
            path
        };
        let sources = |substitutes| Sources {
            esp: sysroot.join("esp"),
            root: sysroot.clone(),
            data: sysroot.join("data"),
            substitutes,
            omit_from_root: Vec::new(),
        };
        let main = scratch.0.join("disk.img");
        let data_image = scratch.0.join("disk-data.img");
        let substitutes = vec![
            Substitute {
                path: PathBuf::from("esp/EFI/seraph/kernel"),
                source: staged("kernel.new", b"tampered kernel"),
            },
            Substitute {
                path: PathBuf::from("services/timed"),
                source: staged("timed.new", b"tampered timed"),
            },
            Substitute {
                path: PathBuf::from("data/note"),
                source: staged("note.new", b"tampered note"),
            },
        ];
        author_images(
            &main,
            &data_image,
            Arch::X86_64,
            DiskLayout::default(),
            &sources(substitutes),
        )
        .unwrap();

        let mut image = File::open(&main).unwrap();
        let file = |bytes: &[u8]| Some(Node::File(bytes.to_vec()));
        let esp = read_volume(&mut image, IMAGE_MARGIN, 512).unwrap();
        assert_eq!(
            esp.get("/EFI/seraph/kernel"),
            file(b"tampered kernel").as_ref()
        );
        let root = read_volume(&mut image, IMAGE_MARGIN + ESP_PARTITION_SIZE, 512).unwrap();
        assert_eq!(
            root.get("/services/timed"),
            file(b"tampered timed").as_ref()
        );
        assert_eq!(
            root.get("/services/drivers/timed"),
            file(b"driver").as_ref()
        );
        let data = read_volume(
            &mut image,
            IMAGE_MARGIN + ESP_PARTITION_SIZE + ROOT_PARTITION_SIZE,
            512,
        )
        .unwrap();
        assert_eq!(data.get("/note"), file(b"tampered note").as_ref());
        assert_eq!(fs::read(sysroot.join("services/timed")).unwrap(), b"timed");

        for path in [
            "services/absent",
            "services/drivers",
            "esp",
            "/services/timed",
        ]
        {
            let refused = vec![Substitute {
                path: PathBuf::from(path),
                source: staged("refused.new", b"x"),
            }];
            author_images(
                &main,
                &data_image,
                Arch::X86_64,
                DiskLayout::default(),
                &sources(refused),
            )
            .expect_err(path);
        }
    }

    // Defect caught: the installed kernel and bootloader left off the root
    // partition, so the root filesystem holds no copy the ESP derives from,
    // or the build's metadata or the ESP tree packed onto it.
    #[test]
    fn the_root_partition_carries_the_installed_boot_files_and_no_metadata()
    {
        use crate::fat_read::{Node, read_volume};

        let scratch = Scratch::new("root-content");
        let sysroot = scratch.0.join("sysroot");
        for (path, bytes) in [
            ("boot/kernel", b"kernel".as_slice()),
            ("boot/boot.efi", b"bootloader"),
            ("esp/EFI/seraph/kernel", b"kernel"),
            (".arch", b"x86_64"),
            (".harness", b"init\n"),
        ]
        {
            let full = sysroot.join(path);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(&full, bytes).unwrap();
        }
        let main = scratch.0.join("disk.img");
        let sources = Sources {
            esp: sysroot.join("esp"),
            root: sysroot.clone(),
            data: sysroot.join("data"),
            substitutes: Vec::new(),
            omit_from_root: Vec::new(),
        };
        author_images(
            &main,
            &scratch.0.join("disk-data.img"),
            Arch::X86_64,
            DiskLayout::default(),
            &sources,
        )
        .unwrap();
        let mut image = File::open(&main).unwrap();
        let root = read_volume(&mut image, IMAGE_MARGIN + ESP_PARTITION_SIZE, 512).unwrap();
        let file = |bytes: &[u8]| Some(Node::File(bytes.to_vec()));
        assert_eq!(root.get("/boot/kernel"), file(b"kernel").as_ref());
        assert_eq!(root.get("/boot/boot.efi"), file(b"bootloader").as_ref());
        for absent in ["/.arch", "/.harness", "/esp"]
        {
            assert!(
                !root.keys().any(|path| path.starts_with(absent)),
                "{absent}"
            );
        }
        let esp = read_volume(&mut image, IMAGE_MARGIN, 512).unwrap();
        assert_eq!(esp.get("/EFI/seraph/kernel"), file(b"kernel").as_ref());
    }

    // Defect caught: a services-layer image that still carries a program, a
    // tester or the programs-layer harness, or one that leaves out a services-
    // layer file whose path shares a prefix with an omitted one.
    #[test]
    fn a_services_layer_image_leaves_the_programs_layer_out()
    {
        use crate::fat_read::read_volume;

        let scratch = Scratch::new("services-layer");
        let sysroot = scratch.0.join("sysroot");
        for path in [
            "programs/shell",
            "tests/programs/hello",
            "tests/usertest",
            "tests/svctest",
            "tests/fixtures/programs/leader",
            "config/svcmgr/tests/usertest.svc",
            "config/svcmgr/tests/svctest.svc",
            "config/svcmgr/services/svctest.svc",
        ]
        {
            let full = sysroot.join(path);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(&full, path).unwrap();
        }
        assert!(crate::svctest_stage::services_layer(&sysroot));
        let main = scratch.0.join("disk.img");
        let sources = Sources {
            esp: sysroot.join("esp"),
            root: sysroot.clone(),
            data: sysroot.join("data"),
            substitutes: Vec::new(),
            omit_from_root: crate::svctest_stage::PROGRAMS_LAYER
                .iter()
                .map(PathBuf::from)
                .collect(),
        };
        author_images(
            &main,
            &scratch.0.join("disk-data.img"),
            Arch::X86_64,
            DiskLayout::default(),
            &sources,
        )
        .unwrap();
        let mut image = File::open(&main).unwrap();
        let root = read_volume(&mut image, IMAGE_MARGIN + ESP_PARTITION_SIZE, 512).unwrap();
        for absent in [
            "/programs",
            "/tests/programs",
            "/tests/usertest",
            "/config/svcmgr/tests/usertest.svc",
        ]
        {
            assert!(!root.contains_key(absent), "{absent}");
            assert!(
                !root
                    .keys()
                    .any(|path| path.starts_with(&format!("{absent}/"))),
                "{absent}"
            );
        }
        for present in [
            "/tests/svctest",
            "/tests/fixtures/programs/leader",
            "/config/svcmgr/tests/svctest.svc",
            "/config/svcmgr/services/svctest.svc",
        ]
        {
            assert!(root.contains_key(present), "{present}");
        }
    }

    #[test]
    fn a_file_with_no_gpt_has_no_layout()
    {
        let scratch = Scratch::new("no-layout");
        let main = scratch.0.join("disk.img");
        fs::write(&main, [0u8; 8192]).unwrap();
        image_layout(&main, &scratch.0.join("disk-data.img")).unwrap_err();
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
