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

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::process::Command;

use boot_protocol::role_guids;

use crate::cli::CheckDiskArgs;
use crate::context::Context as BuildContext;
use crate::disk;
use crate::error::{Context, Result, bail, ensure};
use crate::util::{require_tool, step};

/// Entry point for `cargo xtask check-disk`.
///
/// # Errors
/// Fails when `fsck.fat` is not on `PATH`, `disk.img` is absent, an image's GPT does not
/// parse, a partition cannot be copied, or `fsck.fat` does not pass a volume.
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
    Ok(())
}

/// Check each FAT volume of the GPT image at `image` with `fsck`, copying it to `work` first;
/// returns how many it checked.
fn check_image(fsck: &Path, image: &Path, work: &Path) -> Result<usize>
{
    let block = u64::from(disk::logical_block_size(image)?);
    let mut file =
        File::open(image).with_context(|| format!("failed to open {}", image.display()))?;
    let header_block = read_at(&mut file, block, block)?;
    let Ok(header) = vfsd_gpt::parse_header(&header_block)
    else
    {
        bail!("{} has a GPT header vfsd's parser refuses", image.display());
    };
    let scan = vfsd_gpt::collect_partitions(&header, |lba, buf| {
        lba.checked_mul(block)
            .and_then(|at| read_at(&mut file, at, block).ok())
            .filter(|bytes| bytes.len() == buf.len())
            .map(|bytes| buf.copy_from_slice(&bytes))
            .is_some()
    });
    ensure!(
        scan.stop.is_none(),
        "the GPT walk of {} stopped early",
        image.display()
    );

    let stem = image.file_stem().unwrap_or_default().to_string_lossy();
    let mut checked = 0usize;
    for (index, part) in scan.entries.iter().enumerate()
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
