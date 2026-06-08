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

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

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

/// Top-level sysroot subtrees the rootfs mirror owns exclusively: rootfs static
/// files plus the synthesised `data/svctest/` fixtures. The prune pass is
/// authoritative over these and only these. Build-owned trees (`esp/`,
/// `services/`, `programs/`, `tests/`) and metadata (`.arch`, `NvVars`) are
/// deliberately absent, so a scoping mistake cannot delete a binary.
const ROOTFS_MANAGED_ROOTS: &[&str] = &["config", "data"];

/// Mirror `rootfs/` into the sysroot (skipping README.md), then make the mirror
/// authoritative over [`ROOTFS_MANAGED_ROOTS`].
///
/// Each file's destination directory is created as needed. Files are processed
/// in sorted order for deterministic output. To add a new sysroot file, place
/// it under `rootfs/` at the path it should appear in the sysroot — no build
/// changes required.
///
/// After copying, files under the managed roots with no `rootfs/` source (nor a
/// synthesised-fixture origin) are removed, so deleting a file from `rootfs/` is
/// reflected in the sysroot and the disk image on the next build. Build-owned
/// subtrees are never touched. `mkdisk --repack-only` bypasses this whole step
/// to pack a hand-staged sysroot verbatim.
pub fn install_rootfs(ctx: &BuildContext) -> Result<()>
{
    let src_root = ctx.root.join("rootfs");
    if !src_root.exists()
    {
        return Ok(());
    }

    let mut files = collect_files(&src_root)?;
    files.sort();

    let mut keep: HashSet<PathBuf> = HashSet::new();

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
        keep.insert(dst);
    }

    keep.insert(synthesise_svctest_large_bin(ctx)?);
    keep.insert(synthesise_svctest_bench_bin(ctx)?);

    let roots: Vec<PathBuf> = ROOTFS_MANAGED_ROOTS
        .iter()
        .map(|r| ctx.sysroot.join(r))
        .collect();
    prune_stale(&roots, &keep)?;

    Ok(())
}

const SVCTEST_LARGE_BIN_PAGES: usize = 4;
const SVCTEST_LARGE_BIN_PAGE_SIZE: usize = 4096;

/// Emit `/data/svctest/large.bin`, a 16 KiB deterministic fixture
/// consumed by `svctest`'s `fs_release_on_close_phase`. Each 4 KiB page
/// is filled with the ASCII tag `PAGE_NN_` repeated, where `NN` is the
/// page index. The phase asserts the first 8 bytes equal `PAGE_00_` to
/// confirm content integrity across the FS_READ_FRAME / mem_map /
/// release sequence. Treated as a build artifact (synthesised here, not
/// shipped in `rootfs/`). Returns the destination path so `install_rootfs`
/// keeps it through the prune pass.
fn synthesise_svctest_large_bin(ctx: &BuildContext) -> Result<PathBuf>
{
    let dst = ctx.sysroot.join("data/svctest/large.bin");
    if dst.exists()
    {
        return Ok(dst);
    }
    if let Some(parent) = dst.parent()
    {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let total = SVCTEST_LARGE_BIN_PAGES * SVCTEST_LARGE_BIN_PAGE_SIZE;
    let mut buf = Vec::with_capacity(total);
    for page in 0..SVCTEST_LARGE_BIN_PAGES
    {
        let tag = format!("PAGE_{page:02}_");
        let tag_bytes = tag.as_bytes();
        let mut written = 0usize;
        while written < SVCTEST_LARGE_BIN_PAGE_SIZE
        {
            buf.extend_from_slice(tag_bytes);
            written += tag_bytes.len();
        }
    }
    buf.truncate(total);
    fs::write(&dst, &buf).with_context(|| format!("writing {}", dst.display()))?;
    step(&format!("Rootfs: {} (synthesised, 16 KiB)", dst.display()));
    Ok(dst)
}

const SVCTEST_BENCH_BIN_SIZE: usize = 65536;

/// Emit `/data/svctest/bench.bin`, a 64 KiB deterministic fixture
/// consumed by `fsbench` (the FS_READ vs FS_READ_FRAME crossover
/// benchmark). Filled with a byte-position-derived pattern so any
/// read-path corruption shows up as a content mismatch at the byte
/// level. Treated as a build artifact, same pattern as `large.bin`.
/// Returns the destination path (kept through the prune pass).
fn synthesise_svctest_bench_bin(ctx: &BuildContext) -> Result<PathBuf>
{
    let dst = ctx.sysroot.join("data/svctest/bench.bin");
    if dst.exists()
    {
        return Ok(dst);
    }
    if let Some(parent) = dst.parent()
    {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut buf = Vec::with_capacity(SVCTEST_BENCH_BIN_SIZE);
    for i in 0..SVCTEST_BENCH_BIN_SIZE
    {
        #[allow(clippy::cast_possible_truncation)]
        let b = (i & 0xFF) as u8;
        buf.push(b);
    }
    fs::write(&dst, &buf).with_context(|| format!("writing {}", dst.display()))?;
    step(&format!("Rootfs: {} (synthesised, 64 KiB)", dst.display()));
    Ok(dst)
}

/// Make the rootfs mirror authoritative over `roots`: remove every regular file
/// under each root that is not in `keep`. Directories are left in place — an
/// empty `/config/svcmgr/services` is valid (svcmgr reads it at boot) and the
/// disk packer recreates directories as needed. A non-existent root is skipped.
fn prune_stale(roots: &[PathBuf], keep: &HashSet<PathBuf>) -> Result<()>
{
    for root in roots
    {
        if !root.exists()
        {
            continue;
        }
        for f in collect_files(root)?
        {
            if !keep.contains(&f)
            {
                fs::remove_file(&f).with_context(|| format!("pruning {}", f.display()))?;
                step(&format!("Rootfs: pruned {}", f.display()));
            }
        }
    }
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

#[cfg(test)]
mod tests
{
    use super::*;

    /// Create a unique scratch directory under the system temp dir.
    fn scratch(tag: &str) -> PathBuf
    {
        let p = std::env::temp_dir().join(format!(
            "seraph-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    /// `prune_stale` deletes files with no source, keeps those in `keep`
    /// (including a synthesised fixture under `data/`), and never touches a
    /// build-owned tree that sits outside the managed roots.
    #[test]
    fn prune_stale_removes_unkept_spares_kept_and_unmanaged()
    {
        let sysroot = scratch("prune");

        let services = sysroot.join("config/svcmgr/services");
        let tests_dir = sysroot.join("config/svcmgr/tests");
        let data_fix = sysroot.join("data/svctest");
        let build_tree = sysroot.join("services");
        for d in [&services, &tests_dir, &data_fix, &build_tree]
        {
            fs::create_dir_all(d).unwrap();
        }

        let kept = services.join("a.svc");
        let stale = services.join("b.svc");
        let stale_test = tests_dir.join("c.svc");
        let synth = data_fix.join("large.bin");
        let binary = build_tree.join("init");
        for f in [&kept, &stale, &stale_test, &synth, &binary]
        {
            fs::write(f, b"x").unwrap();
        }

        let mut keep = HashSet::new();
        keep.insert(kept.clone());
        keep.insert(synth.clone());

        let roots = vec![sysroot.join("config"), sysroot.join("data")];
        prune_stale(&roots, &keep).unwrap();

        assert!(kept.exists(), "recipe in keep survives");
        assert!(synth.exists(), "synth fixture in keep survives");
        assert!(binary.exists(), "binary outside managed roots untouched");
        assert!(!stale.exists(), "stale recipe pruned");
        assert!(
            !stale_test.exists(),
            "stale recipe in sibling subtree pruned"
        );

        fs::remove_dir_all(&sysroot).unwrap();
    }

    /// A managed root that does not exist on disk is skipped without error.
    #[test]
    fn prune_stale_skips_missing_root()
    {
        let sysroot = scratch("prune-missing");
        let roots = vec![sysroot.join("config")];
        prune_stale(&roots, &HashSet::new()).unwrap();
        fs::remove_dir_all(&sysroot).unwrap();
    }

    /// End-to-end: `install_rootfs` mirrors `rootfs/`, synthesises the fixtures,
    /// and prunes a stale sysroot recipe while leaving a build-owned binary
    /// untouched. Covers `ROOTFS_MANAGED_ROOTS` and the keep-set construction —
    /// the pieces that make the prune safe — which the `prune_stale` unit tests,
    /// rebuilding roots and keep by hand, do not.
    #[test]
    fn install_rootfs_mirrors_synthesises_and_prunes()
    {
        let base = scratch("install");
        let root = base.join("root");
        let sysroot = base.join("sysroot");

        // Source rootfs/: one default recipe and one data file.
        let rootfs_services = root.join("rootfs/config/svcmgr/services");
        fs::create_dir_all(&rootfs_services).unwrap();
        fs::write(rootfs_services.join("procmgr.svc"), b"binary = /services/procmgr\n").unwrap();
        fs::create_dir_all(root.join("rootfs/data")).unwrap();
        fs::write(root.join("rootfs/data/test.txt"), b"marker").unwrap();

        // Pre-existing sysroot: a stale recipe under a managed root (no rootfs
        // source) and a build-owned binary outside the managed roots.
        let sys_services = sysroot.join("config/svcmgr/services");
        fs::create_dir_all(&sys_services).unwrap();
        fs::write(sys_services.join("stale.svc"), b"binary = /services/stale\n").unwrap();
        let bin_dir = sysroot.join("services");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::write(bin_dir.join("procmgr"), b"\x7fELF").unwrap();

        let ctx = BuildContext {
            root: root.clone(),
            sysroot: sysroot.clone(),
            target_dir: base.join("target"),
        };
        install_rootfs(&ctx).unwrap();

        assert!(sys_services.join("procmgr.svc").exists(), "rootfs recipe mirrored");
        assert!(sysroot.join("data/test.txt").exists(), "rootfs data file mirrored");
        assert!(sysroot.join("data/svctest/large.bin").exists(), "large fixture kept");
        assert!(sysroot.join("data/svctest/bench.bin").exists(), "bench fixture kept");
        assert!(!sys_services.join("stale.svc").exists(), "stale recipe pruned");
        assert!(bin_dir.join("procmgr").exists(), "build-owned binary untouched");

        fs::remove_dir_all(&base).unwrap();
    }
}
