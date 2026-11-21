// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/sysroot.rs

//! Sysroot architecture consistency checks, arch and harness recording, and
//! rootfs installation, the repository's data files included.
//!
//! The sysroot is built for one architecture at a time. The active arch is
//! recorded in `sysroot/.arch`. Switching architectures requires `cargo xtask
//! clean` first to avoid mixing binaries. The harness whose bundle every pack
//! composes is recorded in `sysroot/.harness` ([`record_harness`]).

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Context, Result, bail};

use crate::arch::Arch;
use crate::argparse::{Leaf as _, ValueEnum as _};
use crate::bundle::Harness;
use crate::context::Context as BuildContext;
use crate::util::step;

/// The sysroot file that records the harness every pack composes the bundle
/// of.
const HARNESS_FILE: &str = ".harness";

/// Record `harness` as the one whose bundle every later pack composes
/// (`crate::disk::create_disk_image`): `build` records the init harness,
/// `mkdisk --harness` the one it is given.
///
/// # Errors
///
/// On an I/O failure.
pub fn record_harness(ctx: &BuildContext, harness: Harness) -> Result<()>
{
    fs::create_dir_all(&ctx.sysroot)
        .with_context(|| format!("creating sysroot at {}", ctx.sysroot.display()))?;
    let path = ctx.sysroot.join(HARNESS_FILE);
    fs::write(&path, format!("{}\n", harness.name()))
        .with_context(|| format!("writing {}", path.display()))
}

/// The harness [`record_harness`] recorded, or the init harness when none
/// is.
///
/// # Errors
///
/// When the record cannot be read or names no harness.
pub fn recorded_harness(ctx: &BuildContext) -> Result<Harness>
{
    let path = ctx.sysroot.join(HARNESS_FILE);
    let text = match fs::read_to_string(&path)
    {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Harness::Init),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    Harness::parse(text.trim()).map_err(|e| {
        crate::error::err!(
            "{} names no harness ({e}): run `cargo xtask mkdisk --harness <h>`",
            path.display()
        )
    })
}

/// A file of the repository that the sysroot installs at `install`, outside
/// `rootfs/` since it lives beside the component that reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataFile
{
    /// The install path.
    pub install: &'static str,
    /// The repository-relative path of the file installed there.
    pub source: &'static str,
}

impl DataFile
{
    /// The sysroot-relative path of the installed file.
    pub fn relative(&self) -> String
    {
        self.install.trim_start_matches('/').to_owned()
    }
}

/// The log-level configuration init reads at boot
/// (`services/init/docs/bootstrap.md` § Log levels), on every architecture.
pub const LOG_LEVELS: DataFile = DataFile {
    install: "/config/init/log-levels.conf",
    source: "services/init/log-levels.conf",
};

/// Data files installed on one architecture only: the platform description
/// tables of the machines of that architecture, which list the devices no
/// firmware table describes (`services/devmgr/platform/`).
const ARCH_DATA_FILES: &[(Arch, DataFile)] = &[(
    Arch::Riscv64,
    DataFile {
        install: "/config/devmgr/platform/qemu-virt.platform",
        source: "services/devmgr/platform/qemu-virt.platform",
    },
)];

/// The data files the sysroot installs for `arch`: the architecture's
/// platform tables, then the log-level configuration.
pub fn data_files(arch: Arch) -> Vec<DataFile>
{
    ARCH_DATA_FILES
        .iter()
        .filter(|(a, _)| *a == arch)
        .map(|(_, file)| *file)
        .chain([LOG_LEVELS])
        .collect()
}

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
/// files, the repository's data files ([`install_data_files`]) and the
/// synthesised `data/svctest/` fixtures. The prune pass is
/// authoritative over these and only these. Build-owned trees (`boot/`, `esp/`,
/// `services/`, `programs/`, `tests/`) and metadata (`.arch`, `.harness`, `NvVars`) are
/// deliberately absent, so a scoping mistake cannot delete a binary.
const ROOTFS_MANAGED_ROOTS: &[&str] = &["config", "data"];

/// Directories the image holds empty, which `rootfs/` cannot carry since git
/// tracks no empty directory: `crash/`, where crashd writes cores
/// (services/crashd/docs/operation.md § Core Dump). The disk packer copies a
/// sysroot directory, empty or not.
const EMPTY_DIRS: &[&str] = &["crash"];

/// Mirror `rootfs/` into the sysroot (skipping README.md), install the data
/// files of `arch` ([`install_data_files`]), create
/// [`EMPTY_DIRS`], then make the mirror authoritative over
/// [`ROOTFS_MANAGED_ROOTS`].
///
/// Each file's destination directory is created as needed. Files are processed
/// in sorted order for deterministic output. To add a new sysroot file, place
/// it under `rootfs/` at the path it should appear in the sysroot — no build
/// changes required.
///
/// After copying, files under the managed roots with no `rootfs/` source (nor a
/// data-file or synthesised-fixture origin) are removed, so deleting a file from `rootfs/` is
/// reflected in the sysroot and the disk image on the next build. Build-owned
/// subtrees are never touched. `mkdisk --repack-only` bypasses this whole step
/// to pack a hand-staged sysroot as it stands, except for the data files it
/// still installs ([`install_data_files`]), its objects re-signed as every pack
/// signs them.
pub fn install_rootfs(ctx: &BuildContext, arch: Arch) -> Result<()>
{
    let src_root = ctx.root.join("rootfs");
    let mut files = if src_root.exists()
    {
        collect_files(&src_root)?
    }
    else
    {
        Vec::new()
    };
    files.sort();

    let mut keep: HashSet<PathBuf> = HashSet::new();

    for src in files
    {
        // Skip documentation files that are not part of the sysroot image.
        let rel = src
            .strip_prefix(&src_root)
            .context("src must be under src_root")?;
        if rel.file_name().is_some_and(|n| n == "README.md")
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

    keep.extend(install_data_files(ctx, arch)?);
    keep.insert(synthesise_svctest_large_bin(ctx)?);
    keep.insert(synthesise_svctest_bench_bin(ctx)?);
    keep.insert(synthesise_svctest_verified(ctx)?);
    for dir in EMPTY_DIRS
    {
        let dst = ctx.sysroot.join(dir);
        fs::create_dir_all(&dst).with_context(|| format!("creating {}", dst.display()))?;
        step(&format!("Rootfs: {} (empty directory)", dst.display()));
    }

    let roots: Vec<PathBuf> = ROOTFS_MANAGED_ROOTS
        .iter()
        .map(|r| ctx.sysroot.join(r))
        .collect();
    prune_stale(&roots, &keep)?;

    Ok(())
}

/// Install each data file of `arch` ([`data_files`]): copy its repository
/// source to its install path, unsigned, for the sign that precedes every
/// pack (`crate::signing::sign_sysroot`). Returns the installed paths, which
/// the prune pass keeps.
///
/// # Errors
///
/// When a source is missing or a copy fails.
pub fn install_data_files(ctx: &BuildContext, arch: Arch) -> Result<Vec<PathBuf>>
{
    let mut installed = Vec::new();
    for file in data_files(arch)
    {
        let src = ctx.root.join(file.source);
        let dst = ctx.sysroot.join(file.relative());
        if let Some(parent) = dst.parent()
        {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        fs::copy(&src, &dst)
            .with_context(|| format!("copying {} -> {}", src.display(), dst.display()))?;
        step(&format!("Rootfs: {} (data file)", dst.display()));
        installed.push(dst);
    }
    Ok(installed)
}

const SVCTEST_LARGE_BIN_PAGES: usize = 4;
const SVCTEST_LARGE_BIN_PAGE_SIZE: usize = 4096;

/// Emit `/data/svctest/large.bin`, a 16 KiB deterministic fixture
/// consumed by `svctest`'s `fs_release_on_close_phase`. Each 4 KiB page
/// is filled with the ASCII tag `PAGE_NN_` repeated, where `NN` is the
/// page index. The phase asserts the first 8 bytes equal `PAGE_00_` to
/// confirm content integrity across the `FS_READ_FRAME` / `mem_map` /
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
        buf.extend(tag_bytes.iter().cycle().take(SVCTEST_LARGE_BIN_PAGE_SIZE));
    }
    buf.truncate(total);
    fs::write(&dst, &buf).with_context(|| format!("writing {}", dst.display()))?;
    step(&format!("Rootfs: {} (synthesised, 16 KiB)", dst.display()));
    Ok(dst)
}

const SVCTEST_BENCH_BIN_SIZE: usize = 65536;

/// Emit `/data/svctest/bench.bin`, a 64 KiB deterministic fixture
/// consumed by `fsbench` (the `FS_READ` vs `FS_READ_FRAME` crossover
/// benchmark) and held open by svctest's per-open eviction phase. Filled with a byte-position-derived pattern so any
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
    fs::write(&dst, bench_bin_bytes()).with_context(|| format!("writing {}", dst.display()))?;
    step(&format!("Rootfs: {} (synthesised, 64 KiB)", dst.display()));
    Ok(dst)
}

/// The body of `/data/svctest/signed/verified.dat`. Kept in sync with
/// `services/svctest/src/phases/verified_read.rs`, `VERIFIED_BODY`.
const SVCTEST_VERIFIED_BODY: &[u8] = b"seraph: the body procmgr's verified read returns\n";

/// Emit `/data/svctest/signed/verified.dat`, the fixture svctest's
/// `procmgr_read_verified` phase reads through procmgr's verified read: a
/// file under a data tree, which the sign before every pack signs in the
/// data role under its install path (`crate::signing::sign_sysroot`).
/// Written only when absent, so the signed file a pack left stands. Returns
/// the destination path (kept through the prune pass).
fn synthesise_svctest_verified(ctx: &BuildContext) -> Result<PathBuf>
{
    let dst = ctx.sysroot.join("data/svctest/signed/verified.dat");
    if dst.exists()
    {
        return Ok(dst);
    }
    if let Some(parent) = dst.parent()
    {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(&dst, SVCTEST_VERIFIED_BODY).with_context(|| format!("writing {}", dst.display()))?;
    step(&format!(
        "Rootfs: {} (synthesised, data role)",
        dst.display()
    ));
    Ok(dst)
}

/// The content of `bench.bin`: byte `i` is `i` modulo 256.
fn bench_bin_bytes() -> Vec<u8>
{
    (0..=u8::MAX).cycle().take(SVCTEST_BENCH_BIN_SIZE).collect()
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

    /// A new, empty directory under the system temp dir, unique to this
    /// process and call. The tests run in parallel threads of one process,
    /// so the name carries a per-process sequence number rather than a clock
    /// reading two calls can share; a directory an earlier process of the
    /// same id left behind is removed first.
    fn scratch(tag: &str) -> PathBuf
    {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "seraph-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    /// Two calls with one tag, which a clock reading of the same value used
    /// to give one directory, give two distinct directories, each present.
    #[test]
    fn scratch_gives_each_call_its_own_directory()
    {
        let (first, second) = (scratch("scratch-twice"), scratch("scratch-twice"));
        assert_ne!(first, second);
        assert!(first.is_dir() && second.is_dir());
        fs::remove_dir_all(first).unwrap();
        fs::remove_dir_all(second).unwrap();
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

    // Defect caught: a change to how `bench.bin` is generated that alters
    // its size or its position-derived pattern, which the readers compare
    // against.
    #[test]
    fn bench_bin_is_its_position_modulo_256()
    {
        let bytes = bench_bin_bytes();
        assert_eq!(bytes.len(), SVCTEST_BENCH_BIN_SIZE);
        assert!(
            bytes
                .iter()
                .enumerate()
                .all(|(i, &b)| usize::from(b) == i % 256)
        );
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

    /// End-to-end: `install_rootfs` mirrors `rootfs/`, installs the
    /// repository's data files, synthesises the fixtures, and prunes a stale sysroot
    /// recipe while leaving a build-owned binary untouched. Covers `ROOTFS_MANAGED_ROOTS` and the keep-set construction —
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
        fs::write(
            rootfs_services.join("procmgr.svc"),
            b"binary = /services/procmgr\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("rootfs/data")).unwrap();
        fs::write(root.join("rootfs/data/test.txt"), b"marker").unwrap();
        // The repository sources of the data files.
        let arch = Arch::Riscv64;
        let data = data_files(arch);
        for file in &data
        {
            let src = root.join(file.source);
            fs::create_dir_all(src.parent().unwrap()).unwrap();
            fs::write(&src, file.install.as_bytes()).unwrap();
        }

        // Pre-existing sysroot: a stale recipe under a managed root (no rootfs
        // source) and a build-owned binary outside the managed roots.
        let sys_services = sysroot.join("config/svcmgr/services");
        fs::create_dir_all(&sys_services).unwrap();
        fs::write(
            sys_services.join("stale.svc"),
            b"binary = /services/stale\n",
        )
        .unwrap();
        let bin_dir = sysroot.join("services");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::write(bin_dir.join("procmgr"), b"\x7fELF").unwrap();

        let ctx = BuildContext {
            root: root.clone(),
            sysroot: sysroot.clone(),
            target_dir: base.join("target"),
        };
        install_rootfs(&ctx, arch).unwrap();

        assert!(
            sys_services.join("procmgr.svc").exists(),
            "rootfs recipe mirrored"
        );
        assert!(
            sysroot.join("data/test.txt").exists(),
            "rootfs data file mirrored"
        );
        assert!(
            sysroot.join("data/svctest/large.bin").exists(),
            "large fixture kept"
        );
        assert!(
            sysroot.join("data/svctest/bench.bin").exists(),
            "bench fixture kept"
        );
        assert_eq!(
            fs::read(sysroot.join("data/svctest/signed/verified.dat")).unwrap(),
            SVCTEST_VERIFIED_BODY,
            "verified-read fixture kept"
        );
        assert!(
            !sys_services.join("stale.svc").exists(),
            "stale recipe pruned"
        );
        assert!(
            bin_dir.join("procmgr").exists(),
            "build-owned binary untouched"
        );
        assert!(
            sysroot.join("crash").is_dir(),
            "empty image directory created"
        );
        // Defect caught: a data file not installed, or pruned as a file with
        // no `rootfs/` source, so the bundle that names it cannot be composed.
        assert!(data.len() >= 2, "riscv64 installs a platform table");
        for file in &data
        {
            assert_eq!(
                fs::read(sysroot.join(file.relative())).unwrap(),
                file.install.as_bytes()
            );
        }

        fs::remove_dir_all(&base).unwrap();
    }

    // Defect caught: a data file whose source the repository does not hold,
    // an install path that is not one, or an architecture installing the
    // other's platform table.
    #[test]
    fn every_data_file_installs_a_repository_file_at_an_install_path()
    {
        let root = crate::signing::testing::work_tree();
        for arch in [Arch::X86_64, Arch::Riscv64]
        {
            for file in data_files(arch)
            {
                assert!(root.join(file.source).is_file(), "{}", file.source);
                assert!(objsig::name_is_install_path(file.install.as_bytes()));
                assert_eq!(file.relative(), &file.install[1..]);
            }
        }
        let platform = "/config/devmgr/platform/qemu-virt.platform";
        let installs = |arch| -> Vec<&str> { data_files(arch).iter().map(|f| f.install).collect() };
        assert!(installs(Arch::Riscv64).contains(&platform));
        assert!(!installs(Arch::X86_64).contains(&platform));
        for arch in [Arch::X86_64, Arch::Riscv64]
        {
            assert!(installs(arch).contains(&LOG_LEVELS.install));
        }
    }

    // Defect caught: a pack that composes another harness's bundle than the
    // one `build` or `mkdisk --harness` chose, or an unreadable record taken
    // for the init harness, which would sign and boot the wrong `init`.
    #[test]
    fn the_recorded_harness_is_the_last_one_recorded_and_init_by_default()
    {
        let base = scratch("harness");
        let ctx = BuildContext {
            root: base.clone(),
            sysroot: base.join("sysroot"),
            target_dir: base.join("target"),
        };
        assert_eq!(recorded_harness(&ctx).unwrap(), Harness::Init);
        record_harness(&ctx, Harness::Ktest).unwrap();
        assert_eq!(recorded_harness(&ctx).unwrap(), Harness::Ktest);
        record_harness(&ctx, Harness::Init).unwrap();
        assert_eq!(recorded_harness(&ctx).unwrap(), Harness::Init);
        fs::write(ctx.sysroot.join(HARNESS_FILE), "svctest\n").unwrap();
        recorded_harness(&ctx).unwrap_err();
        fs::remove_dir_all(&base).unwrap();
    }
}
