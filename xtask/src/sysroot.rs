// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! sysroot.rs
//!
//! Sysroot architecture consistency checks, arch recording, and rootfs
//! installation.
//!
//! The sysroot is built for one architecture at a time. The active arch is
//! recorded in `sysroot/.arch`. Switching architectures requires `cargo xtask
//! clean` first to avoid mixing binaries.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::arch::Arch;
use crate::context::Context as BuildContext;
use crate::util::step;

/// Check that the sysroot is either absent or was built for `arch`.
///
/// Returns an error on a mismatch and tells the user to run `cargo xtask clean`.
pub fn check_arch(ctx: &BuildContext, arch: Arch) -> Result<()>
{
    let arch_file = ctx.sysroot.join(".arch");
    if !arch_file.exists()
    {
        return Ok(());
    }
    let existing = fs::read_to_string(&arch_file)
        .with_context(|| format!("reading {}", arch_file.display()))?;
    let existing = existing.trim();
    if existing != arch.to_string()
    {
        bail!(
            "sysroot was built for '{existing}', not '{arch}'.\n\
             Run `cargo xtask clean` before switching architectures."
        );
    }
    Ok(())
}

/// Write `arch` to `sysroot/.arch`, creating the sysroot directory if needed.
pub fn record_arch(ctx: &BuildContext, arch: Arch) -> Result<()>
{
    fs::create_dir_all(&ctx.sysroot)
        .with_context(|| format!("creating sysroot at {}", ctx.sysroot.display()))?;
    let arch_file = ctx.sysroot.join(".arch");
    fs::write(&arch_file, arch.to_string())
        .with_context(|| format!("writing {}", arch_file.display()))?;
    Ok(())
}

/// Mirror `rootfs/` into the sysroot, skipping README.md.
///
/// Each file's destination directory is created as needed. Files are processed
/// in sorted order for deterministic output. To add a new sysroot file, place
/// it under `rootfs/` at the path it should appear in the sysroot — no build
/// changes required.
pub fn install_rootfs(ctx: &BuildContext) -> Result<()>
{
    let src_root = ctx.root.join("rootfs");
    if !src_root.exists()
    {
        return Ok(());
    }

    let mut files = collect_files(&src_root)?;
    files.sort();

    for src in files
    {
        // Skip documentation files that are not part of the sysroot image.
        let rel = src
            .strip_prefix(&src_root)
            .expect("src must be under src_root");
        if rel.file_name().map(|n| n == "README.md").unwrap_or(false)
        {
            continue;
        }

        let dst = ctx.sysroot.join(rel);
        if let Some(parent) = dst.parent()
        {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        fs::copy(&src, &dst)
            .with_context(|| format!("copying {} -> {}", src.display(), dst.display()))?;
        step(&format!("Rootfs: {}", dst.display()));
    }

    synthesise_usertest_large_bin(ctx)?;
    synthesise_usertest_bench_bin(ctx)?;

    Ok(())
}

const USERTEST_LARGE_BIN_PAGES: usize = 4;
const USERTEST_LARGE_BIN_PAGE_SIZE: usize = 4096;

/// Emit `/usertest/large.bin`, a 16 KiB deterministic fixture consumed by
/// `usertest`'s `fs_release_on_close_phase`. Each 4 KiB page is filled with
/// the ASCII tag `PAGE_NN_` repeated, where `NN` is the page index. The
/// phase asserts the first 8 bytes equal `PAGE_00_` to confirm content
/// integrity across the FS_READ_FRAME / mem_map / release sequence.
/// Gitignored under `rootfs/usertest/` and treated as a build artifact.
fn synthesise_usertest_large_bin(ctx: &BuildContext) -> Result<()>
{
    let dst = ctx.sysroot.join("usertest/large.bin");
    if dst.exists()
    {
        return Ok(());
    }
    if let Some(parent) = dst.parent()
    {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let total = USERTEST_LARGE_BIN_PAGES * USERTEST_LARGE_BIN_PAGE_SIZE;
    let mut buf = Vec::with_capacity(total);
    for page in 0..USERTEST_LARGE_BIN_PAGES
    {
        let tag = format!("PAGE_{page:02}_");
        let tag_bytes = tag.as_bytes();
        let mut written = 0usize;
        while written < USERTEST_LARGE_BIN_PAGE_SIZE
        {
            buf.extend_from_slice(tag_bytes);
            written += tag_bytes.len();
        }
    }
    buf.truncate(total);
    fs::write(&dst, &buf).with_context(|| format!("writing {}", dst.display()))?;
    step(&format!("Rootfs: {} (synthesised, 16 KiB)", dst.display()));
    Ok(())
}

const USERTEST_BENCH_BIN_SIZE: usize = 65536;

/// Emit `/usertest/bench.bin`, a 64 KiB deterministic fixture consumed by
/// `fsbench` (the FS_READ vs FS_READ_FRAME crossover benchmark). Filled
/// with a byte-position-derived pattern so any read-path corruption shows
/// up as a content mismatch at the byte level. Gitignored and treated as
/// a build artifact, same pattern as `large.bin`.
fn synthesise_usertest_bench_bin(ctx: &BuildContext) -> Result<()>
{
    let dst = ctx.sysroot.join("usertest/bench.bin");
    if dst.exists()
    {
        return Ok(());
    }
    if let Some(parent) = dst.parent()
    {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut buf = Vec::with_capacity(USERTEST_BENCH_BIN_SIZE);
    for i in 0..USERTEST_BENCH_BIN_SIZE
    {
        #[allow(clippy::cast_possible_truncation)]
        let b = (i & 0xFF) as u8;
        buf.push(b);
    }
    fs::write(&dst, &buf).with_context(|| format!("writing {}", dst.display()))?;
    step(&format!("Rootfs: {} (synthesised, 64 KiB)", dst.display()));
    Ok(())
}

/// Recursively collect all regular files under `dir`.
fn collect_files(dir: &Path) -> Result<Vec<std::path::PathBuf>>
{
    let mut result = Vec::new();
    for entry in
        fs::read_dir(dir).with_context(|| format!("reading directory {}", dir.display()))?
    {
        let entry = entry.context("reading directory entry")?;
        let path = entry.path();
        if path.is_dir()
        {
            result.extend(collect_files(&path)?);
        }
        else
        {
            result.push(path);
        }
    }
    Ok(result)
}
