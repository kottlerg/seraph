// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/image_check.rs

//! The check every pack makes of the disk images it has written
//! (`crate::disk::create_disk_image`): every FAT volume read by an independent
//! reader, `fsck.fat -n` (dosfstools), which reports any structure it does not
//! accept and changes nothing, then the ESP of `disk.img` read back against its
//! installed files. No image a pack writes is left unchecked.
//!
//! The check reads the GPT of each image the pack wrote through vfsd's GPT
//! parser, copies each partition other than swap, the one raw partition a pack
//! writes, to a file under `target/xtask/image-check/`, and runs `fsck.fat -n`
//! on the copy. It fails on the first volume `fsck.fat` does not pass, printing
//! what `fsck.fat` printed.
//!
//! It then reads the ESP, the root and the data partition with xtask's FAT
//! reader (`crate::fat_read`) and checks that the root and data partitions hold
//! only what the kind of image the pack wrote holds (`crate::layers::Image`):
//! nothing for the kernel layer's image, no file of the programs layer for a
//! services-layer harness's, no test feature for the default image, and no file
//! the layer record's install rows do not place, each file placed by its install
//! path as `crate::layers::installed` places it. A pack that wrote a file
//! outside its kind fails, naming every such file.
//!
//! It then checks that every object on the ESP equals the installed file it
//! copies, as composition checks the ESP it writes (`crate::esp::check`): the
//! installed files and the bundle lists are those on the root partition, under
//! `/config/bundle/`, or, for the kernel layer's image, whose root partition
//! holds nothing, the sysroot's, whose ktest bundle must then name only files of
//! the kernel layer; the bundle's entries choose the harness. A pack that wrote
//! one side alone fails, naming the object. A pack that writes substitutes in
//! place of installed files (the `signing` case's refusal images,
//! `crate::disk::create_disk_image_substituting`) skips the ESP check, since
//! its ESP is by design no copy of its installed files.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::process::Command;

use boot_protocol::role_guids;
use vfsd_gpt::GptEntry;

use crate::arch::Arch;
use crate::argparse::ValueEnum as _;
use crate::bundle::{self, Harness};
use crate::error::{Context, Result, bail, ensure};
use crate::fat_read::{self, Node};
use crate::layers::{self, Image, Layer, Role};
use crate::util::{require_tool, step};
use crate::{disk, esp, gpt};

/// What the check of a pack's images reads besides the FAT volumes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EspCheck
{
    /// The ESP of the main image against the installed files
    /// ([`check_esp_copies`]).
    Copies,
    /// Nothing: the pack wrote substitutes, so its ESP is no copy of the
    /// installed files by design.
    Skipped,
}

/// Check the images a pack wrote: each FAT volume of `main`, and of `data` when
/// the pack wrote one, with `fsck.fat -n`, copying each volume under `work`
/// first; then that the root and data partitions hold only what an image of the
/// kind `image` holds ([`check_contents`]); then, as `esp` says, the ESP of
/// `main` against the installed files it copies: those on its root partition,
/// or, for the kernel layer's image, whose root partition holds none, those of
/// the sysroot at `sysroot` ([`check_esp_copies`]).
///
/// # Errors
/// Fails when `fsck.fat` is not on `PATH`, an image's GPT does not parse, a
/// partition cannot be copied or read, `fsck.fat` does not pass a volume, a
/// partition holds a file the image's kind does not, or an object on the ESP
/// of `main` is not the installed file it copies.
pub fn check(
    main: &Path,
    data: Option<&Path>,
    esp: EspCheck,
    image: Image,
    sysroot: &Path,
    work: &Path,
) -> Result<()>
{
    let fsck = require_tool("fsck.fat")?;
    fs::create_dir_all(work).with_context(|| format!("failed to create {}", work.display()))?;
    let mut checked = 0usize;
    for image in std::iter::once(main).chain(data)
    {
        checked = checked.saturating_add(check_image(&fsck, image, work)?);
    }
    let volumes = Volumes::read(main, data)?;
    check_contents(&volumes, image)
        .with_context(|| format!("the images of {} (a {})", main.display(), image.label()))?;
    match esp
    {
        EspCheck::Copies =>
        {
            check_esp_copies(&volumes, image, sysroot)
                .with_context(|| format!("the ESP of {}", main.display()))?;
            step(&format!(
                "Image check: fsck.fat passed {checked} FAT volumes; the partitions hold only what \
                 their kind holds ({}); every object on the ESP of {} is its installed file",
                image.label(),
                main.display()
            ));
        }
        EspCheck::Skipped => step(&format!(
            "Image check: fsck.fat passed {checked} FAT volumes; the partitions hold only what \
             their kind holds ({}); the ESP holds substitutes, so it is not checked against the \
             installed files",
            image.label()
        )),
    }
    Ok(())
}

/// The files of the ESP, the root and the data partition of a pack's images,
/// read with xtask's FAT reader, by path from each volume's root, and the
/// architecture the root partition's type names.
struct Volumes
{
    arch: Arch,
    esp: BTreeMap<String, Vec<u8>>,
    root: BTreeMap<String, Vec<u8>>,
    data: BTreeMap<String, Vec<u8>>,
}

impl Volumes
{
    /// Read the ESP and the root partition of `main`, and the data partition
    /// of `data` when the pack wrote one, of `main` otherwise.
    ///
    /// # Errors
    /// When an image's GPT does not parse, it has not one partition of each
    /// role, or a volume does not read.
    fn read(main: &Path, data: Option<&Path>) -> Result<Self>
    {
        let (esp, ()) = read_partition(main, "ESP", |guid| {
            (*guid == gpt::EFI_SYSTEM_PARTITION).then_some(())
        })?;
        let (root, arch) = read_partition(main, "root partition", |guid| match *guid
        {
            role_guids::SERAPH_ROOT_X86_64 => Some(Arch::X86_64),
            role_guids::SERAPH_ROOT_RISCV64 => Some(Arch::Riscv64),
            _ => None,
        })?;
        let (data, ()) = read_partition(data.unwrap_or(main), "data partition", |guid| {
            (*guid == role_guids::SERAPH_DATA).then_some(())
        })?;
        Ok(Self {
            arch,
            esp,
            root,
            data,
        })
    }
}

/// The files of the one partition of the GPT image at `image` whose type GUID
/// `kind` maps to a value, the `what` of the image, and that value.
///
/// # Errors
/// When the image's GPT does not parse, not one partition has such a type, or
/// its volume does not read.
fn read_partition<T>(
    image: &Path,
    what: &str,
    kind: impl Fn(&[u8; 16]) -> Option<T>,
) -> Result<(BTreeMap<String, Vec<u8>>, T)>
{
    let block = u64::from(disk::logical_block_size(image)?);
    let mut file =
        File::open(image).with_context(|| format!("failed to open {}", image.display()))?;
    let parts = partitions(&mut file, image, block)?;
    let (part, value) = one_partition(&parts, kind)
        .with_context(|| format!("the {what} of {}", image.display()))?;
    let offset = part
        .first_lba
        .checked_mul(block)
        .with_context(|| format!("the {what} of {} lies past u64", image.display()))?;
    let tree = fat_read::read_volume(&mut file, offset, u32::try_from(block)?)
        .with_context(|| format!("reading the {what} of {}", image.display()))?;
    Ok((files(tree), value))
}

/// Check that every file of the root and data partitions of `volumes` is one an
/// image of the kind `image` holds, by its install path (its path on the root
/// partition, or `/data` and its path on the data partition), as the layer
/// record places it ([`layers::installed`]).
///
/// # Errors
/// Naming every file the kind does not hold, and every one no install row
/// places.
fn check_contents(volumes: &Volumes, image: Image) -> Result<()>
{
    let files = volumes
        .root
        .iter()
        .map(|(path, bytes)| (path.trim_start_matches('/').to_owned(), bytes))
        .chain(
            volumes
                .data
                .iter()
                .map(|(path, bytes)| (format!("data/{}", path.trim_start_matches('/')), bytes)),
        );
    let mut faults = Vec::new();
    for (install, bytes) in files
    {
        match layers::installed(&install, || Ok(bytes.clone()))
        {
            Ok(placed) if image.holds(placed) =>
            {}
            Ok(placed) => faults.push(format!(
                "/{install}, a {} of the {:?} layer",
                match placed.role
                {
                    Role::System => "system file",
                    Role::Test => "test feature",
                },
                placed.layer
            )),
            Err(e) => faults.push(format!("{e:#}")),
        }
    }
    ensure!(
        faults.is_empty(),
        "they hold files the kind does not:\n  {}",
        faults.join("\n  ")
    );
    Ok(())
}

/// Check that every object on the ESP of `volumes` equals the installed file it
/// copies ([`esp::check`]): the installed files and the bundle lists are those
/// of the root partition, or, for an image of the kernel layer, those of the
/// sysroot at `sysroot`, whose bundle list must then name only files of the
/// kernel layer.
///
/// # Errors
/// When a bundle list does not parse, a sysroot file cannot be read, the ktest
/// bundle names a file above the kernel layer, or the check fails.
fn check_esp_copies(volumes: &Volumes, image: Image, sysroot: &Path) -> Result<()>
{
    let from_sysroot = |install: &str| -> Result<Option<Vec<u8>>> {
        let path = sysroot.join(install.trim_start_matches('/'));
        match fs::read(&path)
        {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
        }
    };
    let from_root =
        |install: &str| -> Result<Option<Vec<u8>>> { Ok(volumes.root.get(install).cloned()) };
    let installed: &dyn Fn(&str) -> Result<Option<Vec<u8>>> = if image == Image::Kernel
    {
        &from_sysroot
    }
    else
    {
        &from_root
    };
    let lists = installed_lists(volumes.arch, installed).context("reading the bundle lists")?;
    if image == Image::Kernel
    {
        let ktest = installed_list(volumes.arch, Harness::Ktest, installed)?
            .context("the sysroot installs no ktest bundle list")?;
        let above: Vec<&String> = std::iter::once(&ktest.init)
            .chain(&ktest.entries)
            .filter(|entry| {
                layers::install_row(entry.trim_start_matches('/'))
                    .is_none_or(|install| install.layer != Layer::Kernel)
            })
            .collect();
        ensure!(
            above.is_empty(),
            "the ktest bundle names {above:?}, which no install row places in the kernel layer"
        );
    }
    esp::check(&volumes.esp, installed, volumes.arch, &lists).context(
        if image == Image::Kernel
        {
            "it is not copies of the sysroot's installed files"
        }
        else
        {
            "it is not copies of the installed files on its root partition"
        },
    )
}

/// The one partition of `parts` whose type GUID `kind` maps to a value, and that value.
///
/// # Errors
/// When no partition, or more than one, has such a type.
fn one_partition<T>(
    parts: &[GptEntry],
    kind: impl Fn(&[u8; 16]) -> Option<T>,
) -> Result<(&GptEntry, T)>
{
    let mut found = parts
        .iter()
        .filter_map(|part| kind(&part.type_guid).map(|value| (part, value)));
    let first = found.next().context("no partition has its type")?;
    ensure!(found.next().is_none(), "two partitions have its type");
    Ok(first)
}

/// The files of a volume's tree, by path from its root, with their bytes.
fn files(tree: BTreeMap<String, Node>) -> BTreeMap<String, Vec<u8>>
{
    tree.into_iter()
        .filter_map(|(path, node)| match node
        {
            Node::File(bytes) => Some((path, bytes)),
            Node::Dir => None,
        })
        .collect()
}

/// The bundle list of each harness that has one for `arch` among the installed
/// files `installed` returns by install path, parsed.
///
/// # Errors
/// When a harness has two lists for `arch`, a list is not UTF-8 or does not
/// parse, or `installed` fails.
fn installed_lists(
    arch: Arch,
    installed: &dyn Fn(&str) -> Result<Option<Vec<u8>>>,
) -> Result<Vec<bundle::BundleList>>
{
    let mut lists = Vec::new();
    for harness in Harness::VARIANTS
    {
        lists.extend(installed_list(arch, *harness, installed)?);
    }
    Ok(lists)
}

/// The bundle list of `harness` for `arch` among the installed files
/// `installed` returns ([`bundle::list_name`]), parsed; `None` when neither of
/// its names is installed.
///
/// # Errors
/// As [`installed_lists`].
fn installed_list(
    arch: Arch,
    harness: Harness,
    installed: &dyn Fn(&str) -> Result<Option<Vec<u8>>>,
) -> Result<Option<bundle::BundleList>>
{
    let path = |name: &str| format!("/{}/{name}", bundle::LIST_DIR);
    let own = format!("{}.{arch}.list", harness.name());
    let shared = format!("{}.list", harness.name());
    if installed(&path(&own))?.is_none() && installed(&path(&shared))?.is_none()
    {
        return Ok(None);
    }
    let name = bundle::list_name(arch, harness, |name| {
        installed(&path(name)).is_ok_and(|bytes| bytes.is_some())
    })?;
    let path = path(&name);
    let bytes = installed(&path)?.with_context(|| format!("{path} is not installed"))?;
    let text = std::str::from_utf8(&bytes).with_context(|| format!("{path} is not UTF-8"))?;
    bundle::parse_list(text)
        .map(Some)
        .with_context(|| format!("parsing {path}"))
}

/// The partitions of the GPT image `image`, open as `file`, of `block`-byte blocks, read
/// through vfsd's parser.
fn partitions(file: &mut File, image: &Path, block: u64) -> Result<Vec<GptEntry>>
{
    let header_block = read_at(file, block, block)?;
    let Ok(header) = vfsd_gpt::parse_header(&header_block, 1)
    else
    {
        bail!("{} has a GPT header vfsd's parser refuses", image.display());
    };
    let scan = vfsd_gpt::collect_partitions(&header, |lba, buf| {
        lba.checked_mul(block)
            .and_then(|at| read_at(file, at, block).ok())
            .filter(|bytes| bytes.len() == buf.len())
            .map(|bytes| buf.copy_from_slice(&bytes))
            .is_some()
    });
    ensure!(
        scan.stop.is_none(),
        "the GPT walk of {} stopped early",
        image.display()
    );
    Ok(scan.entries)
}

/// Check each FAT volume of the GPT image at `image` with `fsck`, copying it to `work` first;
/// returns how many it checked.
fn check_image(fsck: &Path, image: &Path, work: &Path) -> Result<usize>
{
    let block = u64::from(disk::logical_block_size(image)?);
    let mut file =
        File::open(image).with_context(|| format!("failed to open {}", image.display()))?;
    let parts = partitions(&mut file, image, block)?;

    let stem = image.file_stem().unwrap_or_default().to_string_lossy();
    let mut checked = 0usize;
    for (index, part) in parts.iter().enumerate()
    {
        if part.type_guid == role_guids::SERAPH_SWAP
        {
            continue;
        }
        let number = index.saturating_add(1);
        let copy = work.join(format!("{stem}-p{number}.img"));
        let (Some(offset), Some(len)) = (
            part.first_lba.checked_mul(block),
            part.length_lba.checked_mul(block),
        )
        else
        {
            bail!("partition {number} of {} lies past u64", image.display());
        };
        copy_range(&mut file, offset, len, &copy)
            .with_context(|| format!("failed to copy partition {number} of {}", image.display()))?;
        let output = Command::new(fsck)
            .arg("-n")
            .arg(&copy)
            .output()
            .with_context(|| format!("failed to launch {}", fsck.display()))?;
        if !output.status.success()
        {
            bail!(
                "fsck.fat -n does not pass partition {number} of {} ({}):\n{}{}",
                image.display(),
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        fs::remove_file(&copy).with_context(|| format!("failed to remove {}", copy.display()))?;
        checked = checked.saturating_add(1);
    }
    Ok(checked)
}

/// The `len` bytes of `file` at byte `at`.
fn read_at(file: &mut File, at: u64, len: u64) -> Result<Vec<u8>>
{
    file.seek(SeekFrom::Start(at))
        .context("failed to seek in the image")?;
    let mut bytes = Vec::new();
    file.take(len)
        .read_to_end(&mut bytes)
        .context("failed to read the image")?;
    Ok(bytes)
}

/// Copy the `len` bytes of `file` at byte `at` to a new file at `dest`.
fn copy_range(file: &mut File, at: u64, len: u64, dest: &Path) -> Result<()>
{
    file.seek(SeekFrom::Start(at))
        .context("failed to seek in the image")?;
    let mut out =
        File::create(dest).with_context(|| format!("failed to create {}", dest.display()))?;
    let copied = io::copy(&mut file.take(len), &mut out).context("failed to copy")?;
    ensure!(
        copied == len,
        "the image ends {} bytes into the partition",
        copied
    );
    Ok(())
}

#[cfg(test)]
mod tests
{
    use std::path::PathBuf;

    use super::*;
    use crate::fat::{self, Entry, Kind};

    const MIB: u64 = 1024 * 1024;

    /// The FAT tree of the host directory `dir`, in name order.
    fn tree(dir: &Path) -> Vec<Entry>
    {
        let mut paths: Vec<PathBuf> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        paths.sort();
        paths
            .into_iter()
            .map(|path| Entry {
                name: path.file_name().unwrap().to_str().unwrap().to_owned(),
                kind: if path.is_dir()
                {
                    Kind::Dir(tree(&path))
                }
                else
                {
                    let len = fs::metadata(&path).unwrap().len();
                    Kind::File { path, len }
                },
            })
            .collect()
    }

    /// Write `bytes` at `path` under `dir`, creating its directories.
    fn put(dir: &Path, path: &str, bytes: &[u8])
    {
        let full = dir.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, bytes).unwrap();
    }

    /// Write at `image` a riscv64 GPT image of 512-byte blocks holding an ESP, a root and a
    /// data partition of 17 MiB each, with the trees under `esp`, `root` and `data`.
    fn pack(image: &Path, esp: &Path, root: &Path, data: &Path)
    {
        let first = MIB / 512;
        let blocks = 17 * MIB / 512;
        let partitions = [
            gpt::Partition {
                name: "ESP",
                type_guid: gpt::EFI_SYSTEM_PARTITION,
                unique_guid: [1; 16],
                first_lba: first,
                blocks,
                attributes: 0,
            },
            gpt::Partition {
                name: "ROOT",
                type_guid: role_guids::SERAPH_ROOT_RISCV64,
                unique_guid: [2; 16],
                first_lba: first + blocks,
                blocks,
                attributes: 0,
            },
            gpt::Partition {
                name: "DATA",
                type_guid: role_guids::SERAPH_DATA,
                unique_guid: [4; 16],
                first_lba: first + 2 * blocks,
                blocks,
                attributes: 0,
            },
        ];
        let total = 2 * MIB + 3 * 17 * MIB;
        let regions = gpt::encode(&gpt::Table {
            block_size: 512,
            total_blocks: total / 512,
            disk_guid: [3; 16],
            partitions: &partitions,
        })
        .unwrap();
        let mut file = File::create(image).unwrap();
        file.set_len(total).unwrap();
        for region in regions
        {
            file.seek(SeekFrom::Start(region.offset)).unwrap();
            std::io::Write::write_all(&mut file, &region.bytes).unwrap();
        }
        for (part, dir) in partitions.iter().zip([esp, root, data])
        {
            fs::create_dir_all(dir).unwrap();
            fat::write_volume(
                &mut file,
                part.first_lba * 512,
                17 * MIB,
                512,
                1,
                &tree(dir),
            )
            .unwrap();
        }
    }

    /// A riscv64 image at `dir/disk.img` of an ESP and a root partition that agree and a data
    /// partition, from the trees under `dir/esp`, `dir/root` and `dir/data`; returns the
    /// first three paths.
    fn fixture(dir: &Path) -> (PathBuf, PathBuf, PathBuf)
    {
        let _ = fs::remove_dir_all(dir);
        let (esp, root, image) = (dir.join("esp"), dir.join("root"), dir.join("disk.img"));
        put(&dir.join("data"), "notes/a.txt", b"data");
        for (path, bytes) in [
            ("boot/boot.efi", b"MZ bootloader".as_slice()),
            ("boot/kernel", b"\x7fELF kernel"),
            ("services/init", b"\x7fELF init"),
            ("services/vfsd", b"\x7fELF vfsd"),
            ("tests/ktest", b"\x7fELF ktest"),
            (
                "config/bundle/init.list",
                b"init /services/init\n/services/vfsd\n",
            ),
            ("config/bundle/ktest.list", b"init /tests/ktest\n"),
        ]
        {
            put(&root, path, bytes);
        }
        put(&esp, "EFI/seraph/boot.efi", b"MZ bootloader");
        put(&esp, "EFI/BOOT/BOOTRISCV64.EFI", b"MZ bootloader");
        put(&esp, "EFI/seraph/kernel", b"\x7fELF kernel");
        bundle::write_bundle(
            &esp.join("EFI/seraph/bootstrap.bundle"),
            2,
            &[
                ("init".to_owned(), b"\x7fELF init".to_vec()),
                ("/services/vfsd".to_owned(), b"\x7fELF vfsd".to_vec()),
            ],
        )
        .unwrap();
        pack(&image, &esp, &root, &dir.join("data"));
        (esp, root, image)
    }

    /// The ESP check of the image at `image` against its root partition.
    fn esp_copies(image: &Path) -> Result<()>
    {
        check_esp_copies(
            &Volumes::read(image, None)?,
            Image::Harness,
            Path::new("/nonexistent"),
        )
    }

    /// The content check of the image at `image` as an image of the kind `kind`.
    fn contents(image: &Path, kind: Image) -> Result<()>
    {
        check_contents(&Volumes::read(image, None)?, kind)
    }

    /// A directory under the host's temporary directory, unique to this process and `name`.
    fn scratch(name: &str) -> PathBuf
    {
        std::env::temp_dir().join(format!("seraph-image-check-{name}-{}", std::process::id()))
    }

    // Defect caught: an image whose ESP and root partition disagree (a repack that changed one
    // side alone) passing the check, or an image packed from one sysroot refused: the volumes
    // read at the wrong partition, the architecture or the bundle list taken from the wrong
    // place.
    #[test]
    fn an_image_whose_esp_differs_from_its_root_partition_is_refused()
    {
        let dir = scratch("esp");
        let (esp, root, image) = fixture(&dir);
        esp_copies(&image).unwrap();

        put(&root, "services/vfsd", b"\x7fELF vfsd, rebuilt");
        pack(&image, &esp, &root, &dir.join("data"));
        let error = format!("{:#}", esp_copies(&image).unwrap_err());
        assert!(
            error.contains("entry /services/vfsd differs from its installed file /services/vfsd"),
            "{error}"
        );
        put(&root, "services/vfsd", b"\x7fELF vfsd");
        put(&esp, "EFI/seraph/kernel", b"\x7fELF stale kernel");
        pack(&image, &esp, &root, &dir.join("data"));
        let error = format!("{:#}", esp_copies(&image).unwrap_err());
        assert!(error.contains("/EFI/seraph/kernel differs"), "{error}");
        let _ = fs::remove_dir_all(&dir);
    }

    // Defect caught: a pack's check passing a volume the independent reader refuses (fsck.fat
    // not run on every partition, or its failure taken for a pass).
    #[test]
    fn an_image_with_a_volume_fsck_refuses_is_refused()
    {
        let dir = scratch("fsck");
        let (_, _, image) = fixture(&dir);
        let work = dir.join("work");
        check(&image, None, EspCheck::Copies, Image::Harness, &dir, &work).unwrap();

        // The root partition's boot sector claims clusters of no sectors.
        let mut file = fs::OpenOptions::new().write(true).open(&image).unwrap();
        file.seek(SeekFrom::Start(MIB + 17 * MIB + 13)).unwrap();
        std::io::Write::write_all(&mut file, &[0]).unwrap();
        drop(file);
        let error = format!(
            "{:#}",
            check(&image, None, EspCheck::Skipped, Image::Harness, &dir, &work).unwrap_err()
        );
        assert!(
            error.contains("fsck.fat -n does not pass partition 2"),
            "{error}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // Defect caught: a substituting pack (a refusal image of the signing case) refused for the
    // ESP it writes on purpose, or its volumes and partitions left unchecked.
    #[test]
    fn a_substituted_image_skips_the_esp_check()
    {
        let dir = scratch("substituted");
        let (esp, root, image) = fixture(&dir);
        put(&esp, "EFI/seraph/kernel", b"\x7fELF tampered kernel");
        // The `signing` case's tampered recipe: a body byte that is no UTF-8.
        put(
            &root,
            "config/svcmgr/services/timed.svc",
            b"binary = /services/timed\n\xff\n",
        );
        pack(&image, &esp, &root, &dir.join("data"));
        let work = dir.join("work");
        check(&image, None, EspCheck::Copies, Image::Harness, &dir, &work).unwrap_err();
        check(&image, None, EspCheck::Skipped, Image::Harness, &dir, &work).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
    // Defect caught: an image holding what its kind does not (a test feature on the default
    // image, a program on a services-layer image, anything on the root or data partition of the
    // kernel layer's), or a file no install row places, passing the check; or a recipe judged
    // by its path alone, so a staged copy that starts a program passes on a services-layer
    // image.
    #[test]
    fn an_image_holding_what_its_kind_does_not_is_refused()
    {
        let dir = scratch("kinds");
        let (esp, root, image) = fixture(&dir);
        let data = dir.join("data");
        contents(&image, Image::Harness).unwrap();
        contents(&image, Image::Services).unwrap();
        let error = format!("{:#}", contents(&image, Image::Default).unwrap_err());
        assert!(
            error.contains("/tests/ktest, a test feature of the Kernel layer")
                && error.contains("/config/bundle/ktest.list"),
            "{error}"
        );
        let error = format!("{:#}", contents(&image, Image::Kernel).unwrap_err());
        assert!(
            error.contains("/services/vfsd") && error.contains("/data/notes/a.txt"),
            "{error}"
        );

        put(&root, "programs/shell", b"\x7fELF shell");
        put(
            &root,
            "config/svcmgr/services/sessiond.svc",
            b"binary = /services/sessiond\nargv = sessiond /programs/shell\n",
        );
        pack(&image, &esp, &root, &data);
        contents(&image, Image::Harness).unwrap();
        let error = format!("{:#}", contents(&image, Image::Services).unwrap_err());
        assert!(
            error.contains("/programs/shell, a system file of the Programs layer")
                && error.contains(
                    "/config/svcmgr/services/sessiond.svc, a system file of the Programs layer"
                ),
            "{error}"
        );

        put(&root, "stray/file", b"?");
        pack(&image, &esp, &root, &data);
        let error = format!("{:#}", contents(&image, Image::Harness).unwrap_err());
        assert!(error.contains("stray/file: no install row"), "{error}");
        let _ = fs::remove_dir_all(&dir);
    }

    // Defect caught: the ESP of the kernel layer's image, whose root partition holds nothing,
    // refused for lacking installed files to compare, or held to nothing; or a ktest bundle
    // carrying a file above the kernel layer passing.
    #[test]
    fn the_kernel_image_s_esp_is_checked_against_the_sysroot()
    {
        let dir = scratch("kernel");
        let (esp, sysroot, image) = fixture(&dir);
        let empty = dir.join("empty");
        bundle::write_bundle(
            &esp.join("EFI/seraph/bootstrap.bundle"),
            1,
            &[("init".to_owned(), b"\x7fELF ktest".to_vec())],
        )
        .unwrap();
        pack(&image, &esp, &empty, &empty);
        let volumes = Volumes::read(&image, None).unwrap();
        check_contents(&volumes, Image::Kernel).unwrap();
        check_esp_copies(&volumes, Image::Kernel, &sysroot).unwrap();
        check_esp_copies(&volumes, Image::Harness, &sysroot).unwrap_err();

        put(
            &sysroot,
            "config/bundle/ktest.list",
            b"init /tests/ktest\n/services/vfsd\n",
        );
        bundle::write_bundle(
            &esp.join("EFI/seraph/bootstrap.bundle"),
            2,
            &[
                ("init".to_owned(), b"\x7fELF ktest".to_vec()),
                ("/services/vfsd".to_owned(), b"\x7fELF vfsd".to_vec()),
            ],
        )
        .unwrap();
        pack(&image, &esp, &empty, &empty);
        let volumes = Volumes::read(&image, None).unwrap();
        let error = format!(
            "{:#}",
            check_esp_copies(&volumes, Image::Kernel, &sysroot).unwrap_err()
        );
        assert!(
            error.contains("names [\"/services/vfsd\"], which no install row places in the kernel"),
            "{error}"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
