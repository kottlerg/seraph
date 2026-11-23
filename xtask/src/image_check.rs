// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/image_check.rs

//! The check every pack makes of the disk images it has written
//! (`crate::disk::create_disk_image`): every FAT volume read by an independent
//! reader, `fsck.fat -n` (dosfstools), which reports any structure it does not
//! accept and changes nothing, then the ESP of `disk.img` read back against its
//! root partition. No image a pack writes is left unchecked.
//!
//! The check reads the GPT of each image the pack wrote through vfsd's GPT
//! parser, copies each partition other than swap, the one raw partition a pack
//! writes, to a file under `target/xtask/image-check/`, and runs `fsck.fat -n`
//! on the copy. It fails on the first volume `fsck.fat` does not pass, printing
//! what `fsck.fat` printed.
//!
//! It then reads the ESP and the root partition of `disk.img` with xtask's FAT
//! reader (`crate::fat_read`) and checks that every object on the ESP equals the
//! installed file on the root partition it copies, as composition checks the ESP
//! it writes (`crate::esp::check`): the bundle list is read from the root
//! partition's `/config/bundle/`, and the bundle's entries choose the harness. A
//! pack that wrote one side alone fails, naming the object. A pack that writes
//! substitutes in place of installed files (the `signing` case's refusal images,
//! `crate::disk::create_disk_image_substituting`) makes the `fsck.fat` check
//! alone, since its ESP is by design no copy of its root partition.

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
use crate::util::{require_tool, step};
use crate::{disk, esp, gpt};

/// What the check of a pack's images reads besides the FAT volumes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EspCheck
{
    /// The ESP of the main image against its root partition
    /// ([`check_esp_copies`]).
    Copies,
    /// Nothing: the pack wrote substitutes, so its ESP is no copy of its root
    /// partition by design.
    Skipped,
}

/// Check the images a pack wrote: each FAT volume of `main`, and of `data` when
/// the pack wrote one, with `fsck.fat -n`, copying each volume under `work`
/// first; then, as `esp` says, the ESP of `main` against its root partition.
///
/// # Errors
/// Fails when `fsck.fat` is not on `PATH`, an image's GPT does not parse, a
/// partition cannot be copied, `fsck.fat` does not pass a volume, or an object
/// on the ESP of `main` is not its installed file on the root partition
/// ([`check_esp_copies`]).
pub fn check(main: &Path, data: Option<&Path>, esp: EspCheck, work: &Path) -> Result<()>
{
    let fsck = require_tool("fsck.fat")?;
    fs::create_dir_all(work).with_context(|| format!("failed to create {}", work.display()))?;
    let mut checked = 0usize;
    for image in std::iter::once(main).chain(data)
    {
        checked = checked.saturating_add(check_image(&fsck, image, work)?);
    }
    match esp
    {
        EspCheck::Copies =>
        {
            check_esp_copies(main)?;
            step(&format!(
                "Image check: fsck.fat passed {checked} FAT volumes; every object on the ESP of \
                 {} is its installed file",
                main.display()
            ));
        }
        EspCheck::Skipped => step(&format!(
            "Image check: fsck.fat passed {checked} FAT volumes; the ESP holds substitutes, \
             so it is not checked against the root partition"
        )),
    }
    Ok(())
}

/// Check that every object on the ESP of the GPT image at `image` equals the installed file on
/// its root partition that it copies ([`esp::check`]), the root partition's type giving the
/// architecture and its `/config/bundle/` the bundle lists.
///
/// # Errors
/// When the image's GPT does not parse, it has not one ESP and one Seraph root partition, a
/// volume does not read, a bundle list does not parse, or the check fails.
fn check_esp_copies(image: &Path) -> Result<()>
{
    let block = u64::from(disk::logical_block_size(image)?);
    let mut file =
        File::open(image).with_context(|| format!("failed to open {}", image.display()))?;
    let parts = partitions(&mut file, image, block)?;
    let (esp_part, ()) = one_partition(&parts, |guid| {
        (*guid == gpt::EFI_SYSTEM_PARTITION).then_some(())
    })
    .with_context(|| format!("the ESP of {}", image.display()))?;
    let (root_part, arch) = one_partition(&parts, |guid| match *guid
    {
        role_guids::SERAPH_ROOT_X86_64 => Some(Arch::X86_64),
        role_guids::SERAPH_ROOT_RISCV64 => Some(Arch::Riscv64),
        _ => None,
    })
    .with_context(|| format!("the root partition of {}", image.display()))?;
    let mut volume = |part: &GptEntry, what: &str| -> Result<BTreeMap<String, Vec<u8>>> {
        let offset = part
            .first_lba
            .checked_mul(block)
            .with_context(|| format!("the {what} of {} lies past u64", image.display()))?;
        let tree = fat_read::read_volume(&mut file, offset, u32::try_from(block)?)
            .with_context(|| format!("reading the {what} of {}", image.display()))?;
        Ok(files(tree))
    };
    let esp_files = volume(esp_part, "ESP")?;
    let root_files = volume(root_part, "root partition")?;
    let lists = Harness::VARIANTS
        .iter()
        .map(|harness| installed_list(&root_files, arch, *harness))
        .collect::<Result<Vec<_>>>()
        .with_context(|| format!("reading the bundle lists of {}", image.display()))?;
    let installed =
        |install: &str| -> Result<Option<Vec<u8>>> { Ok(root_files.get(install).cloned()) };
    esp::check(&esp_files, &installed, arch, &lists).with_context(|| {
        format!(
            "the ESP of {} is not copies of the installed files on its root partition",
            image.display()
        )
    })
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

/// The bundle list of `harness` for `arch` that the root volume's `root_files` install under
/// `/config/bundle/` ([`bundle::list_name`]), parsed.
fn installed_list(
    root_files: &BTreeMap<String, Vec<u8>>,
    arch: Arch,
    harness: Harness,
) -> Result<bundle::BundleList>
{
    let path = |name: &str| format!("/{}/{name}", bundle::LIST_DIR);
    let name = bundle::list_name(arch, harness, |name| root_files.contains_key(&path(name)))?;
    let path = path(&name);
    let text = root_files
        .get(&path)
        .map(|bytes| std::str::from_utf8(bytes))
        .transpose()
        .with_context(|| format!("{path} is not UTF-8"))?
        .with_context(|| format!("{path} is not installed"))?;
    bundle::parse_list(text).with_context(|| format!("parsing {path}"))
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

    /// Write at `image` a riscv64 GPT image of 512-byte blocks holding an ESP of 17 MiB with
    /// the tree under `esp` and a root partition of 17 MiB with the tree under `root`.
    fn pack(image: &Path, esp: &Path, root: &Path)
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
            },
            gpt::Partition {
                name: "ROOT",
                type_guid: role_guids::SERAPH_ROOT_RISCV64,
                unique_guid: [2; 16],
                first_lba: first + blocks,
                blocks,
            },
        ];
        let total = 2 * MIB + 2 * 17 * MIB;
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
        for (part, dir) in partitions.iter().zip([esp, root])
        {
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

    /// A riscv64 image at `dir/disk.img` of an ESP and a root partition that agree, from the
    /// trees under `dir/esp` and `dir/root`; returns those three paths.
    fn fixture(dir: &Path) -> (PathBuf, PathBuf, PathBuf)
    {
        let _ = fs::remove_dir_all(dir);
        let (esp, root, image) = (dir.join("esp"), dir.join("root"), dir.join("disk.img"));
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
        pack(&image, &esp, &root);
        (esp, root, image)
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
        check_esp_copies(&image).unwrap();

        put(&root, "services/vfsd", b"\x7fELF vfsd, rebuilt");
        pack(&image, &esp, &root);
        let error = format!("{:#}", check_esp_copies(&image).unwrap_err());
        assert!(
            error.contains("entry /services/vfsd differs from its installed file /services/vfsd"),
            "{error}"
        );
        put(&root, "services/vfsd", b"\x7fELF vfsd");
        put(&esp, "EFI/seraph/kernel", b"\x7fELF stale kernel");
        pack(&image, &esp, &root);
        let error = format!("{:#}", check_esp_copies(&image).unwrap_err());
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
        check(&image, None, EspCheck::Copies, &work).unwrap();

        // The root partition's boot sector claims clusters of no sectors.
        let mut file = fs::OpenOptions::new().write(true).open(&image).unwrap();
        file.seek(SeekFrom::Start(MIB + 17 * MIB + 13)).unwrap();
        std::io::Write::write_all(&mut file, &[0]).unwrap();
        drop(file);
        let error = format!(
            "{:#}",
            check(&image, None, EspCheck::Skipped, &work).unwrap_err()
        );
        assert!(
            error.contains("fsck.fat -n does not pass partition 2"),
            "{error}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // Defect caught: a substituting pack (a refusal image of the signing case) refused for the
    // ESP it writes on purpose, or its volumes left unchecked.
    #[test]
    fn a_substituted_image_is_checked_by_fsck_alone()
    {
        let dir = scratch("substituted");
        let (esp, root, image) = fixture(&dir);
        put(&esp, "EFI/seraph/kernel", b"\x7fELF tampered kernel");
        pack(&image, &esp, &root);
        let work = dir.join("work");
        check(&image, None, EspCheck::Copies, &work).unwrap_err();
        check(&image, None, EspCheck::Skipped, &work).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}
