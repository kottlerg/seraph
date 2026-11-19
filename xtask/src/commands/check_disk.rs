// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/check_disk.rs

//! Check-disk command: check every FAT volume of the authored disk images with an
//! independent reader, `fsck.fat -n` (dosfstools), which reports any structure it does not
//! accept and changes nothing.
//!
//! The command reads the GPT of `disk.img`, and of `disk-data.img` when it is there, through
//! vfsd's GPT parser, copies each partition other than swap, the one raw partition `mkdisk`
//! writes, to a file under `target/xtask/check-disk/`, and runs `fsck.fat -n` on the copy. It
//! fails on the first volume `fsck.fat` does not pass, printing what `fsck.fat` printed.
//!
//! It then reads the ESP and the root partition of `disk.img` with xtask's FAT reader
//! (`crate::fat_read`) and checks that every object on the ESP equals the installed file on the
//! root partition it copies, as composition checks the ESP it writes (`crate::esp::check`): the
//! bundle list is read from the root partition's `/config/bundle/`, and the bundle's entries
//! choose the harness. A repack that changed one side alone fails, naming the object.

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
use crate::cli::CheckDiskArgs;
use crate::context::Context as BuildContext;
use crate::error::{Context, Result, bail, ensure};
use crate::fat_read::{self, Node};
use crate::util::{require_tool, step};
use crate::{disk, esp, gpt};

/// Entry point for `cargo xtask check-disk`.
///
/// # Errors
/// Fails when `fsck.fat` is not on `PATH`, `disk.img` is absent, an image's GPT does not
/// parse, a partition cannot be copied, `fsck.fat` does not pass a volume, or an object on the
/// ESP of `disk.img` is not its installed file on the root partition ([`check_esp_copies`]).
pub fn run(ctx: &BuildContext, _args: &CheckDiskArgs) -> Result<()>
{
    let fsck = require_tool("fsck.fat")?;
    let main = ctx.disk_image();
    ensure!(
        main.is_file(),
        "{} is absent: run `cargo xtask build` or `cargo xtask mkdisk` first",
        main.display()
    );
    let work = ctx.target_dir.join("xtask").join("check-disk");
    fs::create_dir_all(&work).with_context(|| format!("failed to create {}", work.display()))?;
    let data = ctx.data_disk_image();
    let mut checked = 0usize;
    for image in [main, data].iter().filter(|path| path.is_file())
    {
        checked = checked.saturating_add(check_image(&fsck, image, &work)?);
    }
    step(&format!(
        "check-disk: fsck.fat passed {checked} FAT volumes"
    ));
    let main = ctx.disk_image();
    check_esp_copies(&main)?;
    step(&format!(
        "check-disk: every object on the ESP of {} is its installed file",
        main.display()
    ));
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
    let Ok(header) = vfsd_gpt::parse_header(&header_block)
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
        step(&format!(
            "check-disk: {} partition {number}: clean",
            image.display()
        ));
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

    // Defect caught: an image whose ESP and root partition disagree (a repack that changed one
    // side alone) passing check-disk, or an image packed from one sysroot refused: the volumes
    // read at the wrong partition, the architecture or the bundle list taken from the wrong
    // place.
    #[test]
    fn an_image_whose_esp_differs_from_its_root_partition_is_refused()
    {
        let dir = std::env::temp_dir().join(format!("seraph-check-disk-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
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
}
