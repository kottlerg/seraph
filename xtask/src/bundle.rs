// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/bundle.rs

//! Compose the bootloader bundle (`sysroot/esp/EFI/seraph/bootstrap.bundle`)
//! from canonical userspace binaries staged in the sysroot. The format is
//! defined by [`boot_protocol::bundle`] and shared with the bootloader
//! consumer side; this module is the only producer in the tree.
//!
//! Two flavours of bundle are produced, selected by [`Harness`]:
//!
//! - [`Harness::Init`] — default. Pulls `init`, `procmgr`, `memmgr`,
//!   `devmgr`, `vfsd`, `virtio-blk`, `serial`, `framebuffer`, `fatfs`
//!   into the bundle, and the IOMMU driver of the architecture's IOMMU
//!   family: `iommu-vtd` on x86-64, `iommu-riscv` on riscv64; and the
//!   platform description tables of the architecture's machines
//!   (`platform-qemu-virt` on riscv64), from `services/devmgr/platform/`;
//!   and the log-level configuration init reads at boot (`log-levels`), from
//!   `services/init/log-levels.conf`.
//!   `init` is named `"init"`; modules carry their service name. Sources span
//!   `sysroot/services/`, `sysroot/services/drivers/`, and
//!   `sysroot/services/fs/` per each component's install destination.
//! - [`Harness::Ktest`] — pulls `ktest` only, named `"init"`, from
//!   `sysroot/tests/ktest`. Zero module entries. The bootloader's
//!   `step4_parse_bundle` treats this as a monolithic ktest boot per
//!   `boot_protocol::bundle::INIT_ENTRY_NAME` semantics.

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use boot_protocol::bundle as fmt;

use crate::arch::Arch;
use crate::context::Context as BuildContext;
use crate::util::step;

/// Which harness binary to bundle as the `"init"` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Harness
{
    /// Regular userspace init at `sysroot/services/init`. Bundle includes
    /// every service module the system needs to bootstrap userspace.
    #[value(name = "init")]
    Init,
    /// `sysroot/tests/ktest` as the `"init"` entry. Bundle is a single
    /// entry; ktest is monolithic and does not spawn userspace modules.
    #[value(name = "ktest")]
    Ktest,
}

impl Harness
{
    /// Sysroot-relative source path of the harness binary that backs the
    /// bundle's `"init"` entry. The bundle entry itself is always named
    /// `"init"` regardless of source.
    fn init_source(self) -> &'static str
    {
        match self
        {
            Harness::Init => "services/init",
            Harness::Ktest => "tests/ktest",
        }
    }
}

/// Modules that ship in a default-init bundle. init looks them up by
/// the name strings here (via `InitInfo::module_names`, populated by
/// the kernel), so the order is free for the producer's convenience.
/// Each entry is `(bundle_entry_name, sysroot_relative_source_path)`;
/// the bundle-entry name is what init matches against, while the source
/// path follows each binary's `InstallDest` (drivers under
/// `services/drivers/`, fs drivers under `services/fs/`).
///
/// Only **bootstrap-essential** binaries belong here — things needed to
/// read anything off the disk in the first place (`vfsd`, the block
/// driver, the fs driver) and things needed before vfsd is up
/// (`serial` + `framebuffer` for pre-vfsd console output, `memmgr` /
/// `procmgr` / `devmgr` to even bring up userspace). Non-essential
/// drivers live on the rootfs and are loaded by their managing service
/// after vfsd-mount — the per-arch RTC, for example, is loaded by
/// devmgr through its `SET_DRIVERS_DIR` subtree cap; growing the bundle
/// with non-essentials directly wastes permanently-leaked
/// post-`ExitBootServices` UEFI allocation
/// (see `step9_populate_boot_info` in `core/boot/src/main.rs`).
///
/// All entries are mandatory; a missing source binary hard-errors.
/// Order is preserved across builds to keep the disk-image byte-stable.
const MODULES: &[(&str, &str)] = &[
    ("procmgr", "services/procmgr"),
    ("devmgr", "services/devmgr"),
    ("vfsd", "services/vfsd"),
    ("virtio-blk", "services/drivers/virtio-blk"),
    ("serial", "services/drivers/serial"),
    ("framebuffer", "services/drivers/framebuffer"),
    ("fatfs", "services/fs/fatfs"),
    ("memmgr", "services/memmgr"),
];

/// Modules that ship in a default-init bundle on one architecture only, as
/// `(architecture, bundle_entry_name, sysroot_relative_source_path)`, under
/// the same rules as [`MODULES`]: the IOMMU driver of the architecture's
/// IOMMU family, which devmgr spawns before the first DMA-capable driver
/// maps a ring, so before the root filesystem can be read.
const ARCH_MODULES: &[(Arch, &str, &str)] = &[
    (Arch::X86_64, "iommu-vtd", "services/drivers/iommu-vtd"),
    (Arch::Riscv64, "iommu-riscv", "services/drivers/iommu-riscv"),
];

/// Platform description tables that ship in a default-init bundle on one
/// architecture only, as `(architecture, bundle_entry_name,
/// repository_relative_source_path)`: the text tables of the machines of that
/// architecture, which list the devices no firmware table describes. init
/// forwards them to devmgr with the driver modules; devmgr uses the one whose
/// `oem_table_id` equals the XSDT's (`services/devmgr/platform/`).
const ARCH_TABLES: &[(Arch, &str, &str)] = &[(
    Arch::Riscv64,
    "platform-qemu-virt",
    "services/devmgr/platform/qemu-virt.platform",
)];

/// Bundle entry name of the log-level configuration init reads at boot
/// (`services/init/docs/bootstrap.md` § Log levels).
pub const LOG_LEVELS_ENTRY: &str = "log-levels";

/// Repository-relative path of the committed log-level configuration that
/// [`compose`] packs as the [`LOG_LEVELS_ENTRY`] entry of a default-init
/// bundle. It is read from the repository, not the sysroot, so an edit takes
/// effect at the next `cargo xtask compose-bundle`, with no rebuild.
pub const LOG_LEVELS_SOURCE: &str = "services/init/log-levels.conf";

/// Compose a bundle for the chosen harness and write it to
/// `sysroot/esp/EFI/seraph/bootstrap.bundle`, overwriting any existing
/// file. Source binaries are read from per-component sysroot paths
/// driven by each component's [`crate::commands::build::InstallDest`].
///
/// `Harness::Init` bundles `init` plus every entry in [`MODULES`], every
/// entry of [`ARCH_MODULES`] and [`ARCH_TABLES`] for `arch`, and the
/// committed log-level configuration [`LOG_LEVELS_SOURCE`].
/// `Harness::Ktest` bundles only `ktest` as the `init` entry.
pub fn compose(ctx: &BuildContext, arch: Arch, harness: Harness) -> Result<()>
{
    compose_with_levels(ctx, arch, harness, &ctx.root.join(LOG_LEVELS_SOURCE))
}

/// [`compose`], with the [`LOG_LEVELS_ENTRY`] entry of a `Harness::Init`
/// bundle read from `levels` in place of [`LOG_LEVELS_SOURCE`]: the
/// `test-log-level` harness boots a configuration of its own this way.
pub fn compose_with_levels(
    ctx: &BuildContext,
    arch: Arch,
    harness: Harness,
    levels: &Path,
) -> Result<()>
{
    let out_path = ctx.sysroot_efi_seraph().join("bootstrap.bundle");
    let entries = entries(ctx, arch, harness, levels)?;

    let parent = out_path
        .parent()
        .context("compose-bundle: bundle path has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("compose-bundle: create {}", parent.display()))?;

    let entry_count =
        u32::try_from(entries.len()).context("compose-bundle: too many entries for u32")?;
    write_bundle(&out_path, entry_count, &entries)?;

    step(&format!(
        "Bundle: {} ({} entries, harness={:?})",
        out_path.display(),
        entries.len(),
        harness
    ));
    Ok(())
}

/// The `(bundle_entry_name, source_path)` entries of `harness`'s bundle for
/// `arch`, in bundle order, with `levels` as the source of the
/// [`LOG_LEVELS_ENTRY`] entry of a `Harness::Init` bundle. Fails naming the
/// first source that does not exist.
fn entries(
    ctx: &BuildContext,
    arch: Arch,
    harness: Harness,
    levels: &Path,
) -> Result<Vec<(String, PathBuf)>>
{
    let init_src = ctx.sysroot.join(harness.init_source());
    if !init_src.exists()
    {
        anyhow::bail!(
            "compose-bundle: harness binary missing at {} (run `cargo xtask build` first)",
            init_src.display()
        );
    }

    let mut entries: Vec<(String, PathBuf)> = Vec::new();
    // Bundle entry named "init" sources from the chosen harness binary.
    entries.push(("init".to_owned(), init_src));
    if harness == Harness::Init
    {
        let arch_modules = ARCH_MODULES
            .iter()
            .filter(|(a, _, _)| *a == arch)
            .map(|(_, name, source)| (name, source));
        for (name, source) in MODULES.iter().map(|(n, s)| (n, s)).chain(arch_modules)
        {
            let p = ctx.sysroot.join(source);
            if !p.exists()
            {
                anyhow::bail!(
                    "compose-bundle: module binary missing at {} (run `cargo xtask build` first)",
                    p.display()
                );
            }
            entries.push(((*name).to_owned(), p));
        }
        for (_, name, source) in ARCH_TABLES.iter().filter(|(a, _, _)| *a == arch)
        {
            let p = ctx.root.join(source);
            if !p.exists()
            {
                anyhow::bail!("compose-bundle: platform table missing at {}", p.display());
            }
            entries.push(((*name).to_owned(), p));
        }
        if !levels.exists()
        {
            anyhow::bail!(
                "compose-bundle: log-level configuration missing at {}",
                levels.display()
            );
        }
        entries.push((LOG_LEVELS_ENTRY.to_owned(), levels.to_path_buf()));
    }
    Ok(entries)
}

/// Write the bundle file: header, per-entry headers, then bodies aligned
/// to [`fmt::BODY_ALIGNMENT`].
fn write_bundle(out: &Path, entry_count: u32, entries: &[(String, PathBuf)]) -> Result<()>
{
    let mut out_file = fs::File::create(out)
        .with_context(|| format!("compose-bundle: create {}", out.display()))?;

    out_file
        .write_all(&fmt::MAGIC)
        .context("compose-bundle: write magic")?;
    out_file
        .write_all(&fmt::VERSION.to_le_bytes())
        .context("compose-bundle: write version")?;
    out_file
        .write_all(&entry_count.to_le_bytes())
        .context("compose-bundle: write entry_count")?;

    // Compute body offsets up front so the entry header table can be
    // written before the bodies themselves.
    let header_table_len = entries
        .len()
        .checked_mul(fmt::ENTRY_HEADER_SIZE)
        .and_then(|len| u64::try_from(len).ok())
        .context("compose-bundle: entry header table size overflows")?;
    let mut offsets: Vec<u64> = Vec::with_capacity(entries.len());
    let mut cursor = (fmt::HEADER_SIZE as u64)
        .checked_add(header_table_len)
        .context("compose-bundle: bundle size overflows")?;
    let mut sizes: Vec<u64> = Vec::with_capacity(entries.len());
    for (_, path) in entries
    {
        let size = fs::metadata(path)
            .with_context(|| format!("compose-bundle: stat {}", path.display()))?
            .len();
        cursor = align_up(cursor, fmt::BODY_ALIGNMENT)
            .context("compose-bundle: bundle size overflows")?;
        offsets.push(cursor);
        sizes.push(size);
        cursor = cursor
            .checked_add(size)
            .context("compose-bundle: bundle size overflows")?;
    }

    // Entry header table.
    for ((name, _), (&offset, &size)) in entries.iter().zip(offsets.iter().zip(sizes.iter()))
    {
        let mut name_buf = [0u8; fmt::ENTRY_NAME_LEN];
        let nb = name.as_bytes();
        let Some(name_dst) = name_buf.get_mut(..nb.len())
        else
        {
            anyhow::bail!(
                "compose-bundle: entry name `{name}` exceeds {} bytes",
                fmt::ENTRY_NAME_LEN
            );
        };
        name_dst.copy_from_slice(nb);
        out_file
            .write_all(&name_buf)
            .context("compose-bundle: write entry name")?;
        out_file
            .write_all(&offset.to_le_bytes())
            .context("compose-bundle: write entry offset")?;
        out_file
            .write_all(&size.to_le_bytes())
            .context("compose-bundle: write entry size")?;
    }

    // Bodies (aligned).
    for ((_, path), &offset) in entries.iter().zip(offsets.iter())
    {
        out_file
            .seek(SeekFrom::Start(offset))
            .context("compose-bundle: seek to body offset")?;
        let bytes =
            fs::read(path).with_context(|| format!("compose-bundle: read {}", path.display()))?;
        out_file
            .write_all(&bytes)
            .with_context(|| format!("compose-bundle: write body for {}", path.display()))?;
    }

    out_file
        .sync_all()
        .context("compose-bundle: sync bundle file")?;
    Ok(())
}

/// `value` rounded up to the power-of-two `alignment`, or `None` when the
/// result exceeds `u64::MAX`.
fn align_up(value: u64, alignment: u64) -> Option<u64>
{
    debug_assert!(alignment.is_power_of_two());
    let mask = alignment.checked_sub(1)?;
    Some(value.checked_add(mask)? & !mask)
}

#[cfg(test)]
mod tests
{
    use super::*;
    use boot_protocol::bundle as fmt;
    use std::io::Read;

    /// Rounding up is exact within range and `None` past `u64::MAX`.
    #[test]
    fn align_up_reports_overflow()
    {
        assert_eq!(align_up(0, 4096), Some(0));
        assert_eq!(align_up(1, 4096), Some(4096));
        assert_eq!(align_up(4096, 4096), Some(4096));
        assert_eq!(align_up(u64::MAX, 4096), None);
    }

    /// A scratch directory unique to this test process and call.
    fn scratch(tag: &str) -> PathBuf
    {
        let dir = std::env::temp_dir().join(format!(
            "seraph-bundle-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    // Defect caught: a default-init bundle without the log-level
    // configuration, or with the committed file where a harness asked for its
    // own, so init boots every service at info whatever was configured.
    #[test]
    fn an_init_bundle_carries_the_log_level_configuration_it_is_given()
    {
        let root = scratch("levels");
        let ctx = BuildContext {
            root: root.clone(),
            sysroot: root.join("sysroot"),
            target_dir: root.join("target"),
        };
        let arch = Arch::Riscv64;
        let sources = std::iter::once("services/init")
            .chain(MODULES.iter().map(|(_, s)| *s))
            .chain(
                ARCH_MODULES
                    .iter()
                    .filter(|(a, _, _)| *a == arch)
                    .map(|(_, _, s)| *s),
            );
        for source in sources
        {
            let p = ctx.sysroot.join(source);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, b"elf").unwrap();
        }
        for (_, _, source) in ARCH_TABLES.iter().filter(|(a, _, _)| *a == arch)
        {
            let p = root.join(source);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, b"table").unwrap();
        }
        let levels = root.join("levels.conf");
        fs::write(&levels, b"vfsd = debug\n").unwrap();

        let init = entries(&ctx, arch, Harness::Init, &levels).expect("init entries");
        let found: Vec<&PathBuf> = init
            .iter()
            .filter(|(name, _)| name == LOG_LEVELS_ENTRY)
            .map(|(_, path)| path)
            .collect();
        assert_eq!(found, [&levels]);

        // The ktest bundle is the harness alone.
        let ktest_src = ctx.sysroot.join("tests/ktest");
        fs::create_dir_all(ktest_src.parent().unwrap()).unwrap();
        fs::write(&ktest_src, b"elf").unwrap();
        let ktest = entries(&ctx, arch, Harness::Ktest, &levels).expect("ktest entries");
        assert_eq!(ktest, [("init".to_owned(), ktest_src)]);

        // A missing configuration is an error, as a missing module is.
        entries(&ctx, arch, Harness::Init, &root.join("absent.conf")).unwrap_err();

        let _ = fs::remove_dir_all(&root);
    }

    /// Two-file round trip: write a bundle from two tiny "binary" files,
    /// parse it back via the shared format reader, and verify each
    /// entry's name, offset alignment, and body bytes.
    #[test]
    fn write_bundle_round_trip()
    {
        let tmp = std::env::temp_dir().join(format!(
            "seraph-bundle-rt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&tmp).unwrap();

        let a_path = tmp.join("a");
        let b_path = tmp.join("b");
        fs::write(&a_path, b"alpha").unwrap();
        fs::write(&b_path, b"beta--").unwrap();

        let out = tmp.join("bundle.bin");
        let entries = vec![("init".to_owned(), a_path), ("svc".to_owned(), b_path)];
        write_bundle(&out, 2, &entries).expect("write_bundle");

        // Read back and parse.
        let mut buf = Vec::new();
        fs::File::open(&out).unwrap().read_to_end(&mut buf).unwrap();
        let hdr = fmt::parse_header(&buf).expect("parse_header");
        assert_eq!(hdr.magic, fmt::MAGIC);
        assert_eq!(hdr.version, fmt::VERSION);
        assert_eq!(hdr.entry_count, 2);

        let e0 = fmt::entry_at(&buf, 0).expect("entry 0");
        assert_eq!(fmt::name_str(&e0.name), b"init");
        assert_eq!(e0.size, 5);
        assert!(e0.offset.is_multiple_of(fmt::BODY_ALIGNMENT));
        let body0 = &buf
            [usize::try_from(e0.offset).unwrap()..usize::try_from(e0.offset + e0.size).unwrap()];
        assert_eq!(body0, b"alpha");

        let e1 = fmt::entry_at(&buf, 1).expect("entry 1");
        assert_eq!(fmt::name_str(&e1.name), b"svc");
        assert_eq!(e1.size, 6);
        assert!(e1.offset.is_multiple_of(fmt::BODY_ALIGNMENT));
        let body1 = &buf
            [usize::try_from(e1.offset).unwrap()..usize::try_from(e1.offset + e1.size).unwrap()];
        assert_eq!(body1, b"beta--");

        let _ = fs::remove_dir_all(&tmp);
    }
}
