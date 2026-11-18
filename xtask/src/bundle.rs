// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/bundle.rs

//! Compose the bootloader bundle (`sysroot/esp/EFI/seraph/bootstrap.bundle`)
//! from the installed files of the sysroot. The format is defined by
//! [`boot_protocol::bundle`] and shared with the bootloader consumer side;
//! this module is the only producer in the tree.
//!
//! Two flavours of bundle are produced, selected by [`Harness`]:
//!
//! - [`Harness::Init`] — default. Copies `/services/init` into the `init`
//!   slot, every image [`MODULES`] names, the IOMMU driver of the
//!   architecture's IOMMU family ([`ARCH_MODULES`]: `iommu-vtd` on x86-64,
//!   `iommu-riscv` on riscv64), and the data entries of the architecture
//!   ([`data_entries`]): the log-level configuration init reads at boot and
//!   the platform description tables of the architecture's machines
//!   (`qemu-virt.platform` on riscv64).
//! - [`Harness::Ktest`] — copies `/tests/ktest` into the `init` slot alone.
//!   Zero module entries. The bootloader's `step4_parse_bundle` treats this
//!   as a monolithic ktest boot per `boot_protocol::bundle::INIT_ENTRY_NAME`
//!   semantics.
//!
//! Every entry but `init` is named by its install path, and every entry is
//! its installed file byte for byte (docs/boot-media.md § The ESP). The
//! composer signs nothing: the sysroot is signed first
//! ([`crate::signing::sign_for_harness`]), and the composer verifies each
//! entry as the bootloader will, under the trust store the installed
//! bootloader embeds, before it writes the bundle.

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{Context, Result, bail, err};
use boot_protocol::bundle as fmt;
use objsig::{Expectation, Role, RoleSet, TrustStore};

use crate::arch::Arch;
use crate::context::Context as BuildContext;
use crate::signing::{INIT_SLOT, body_of, bootloader_images, check_installed_store, objsig_arch};
use crate::util::step;

crate::argparse::value_enum! {
    /// Which harness binary to bundle as the `"init"` entry.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// Images that ship in a default-init bundle, by install path, which is also
/// the name of each one's entry. init looks them up by the names here (in the
/// `InitInfo` name table the kernel fills), so the order is free for the
/// producer's convenience.
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
/// All entries are mandatory; a missing installed image hard-errors.
/// Order is preserved across builds to keep the disk-image byte-stable.
const MODULES: &[&str] = &[
    "/services/procmgr",
    "/services/devmgr",
    "/services/vfsd",
    "/services/drivers/virtio-blk",
    "/services/drivers/serial",
    "/services/drivers/framebuffer",
    "/services/fs/fatfs",
    "/services/memmgr",
];

/// Images that ship in a default-init bundle on one architecture only, as
/// `(architecture, install_path)`, under the same rules as [`MODULES`]: the
/// IOMMU driver of the architecture's IOMMU family, which devmgr spawns
/// before the first DMA-capable driver maps a ring, so before the root
/// filesystem can be read.
const ARCH_MODULES: &[(Arch, &str)] = &[
    (Arch::X86_64, "/services/drivers/iommu-vtd"),
    (Arch::Riscv64, "/services/drivers/iommu-riscv"),
];

/// A data entry of a default-init bundle: a file of the repository that the
/// sysroot installs at `install`, signed there with the boot-module role
/// ([`crate::signing::sign_sysroot`]), and that the bundle copies under that
/// name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataEntry
{
    /// The install path, and the name of the entry.
    pub install: &'static str,
    /// The repository-relative path of the file installed there.
    pub source: &'static str,
}

impl DataEntry
{
    /// The sysroot-relative path of the installed file.
    pub fn relative(&self) -> String
    {
        self.install.trim_start_matches('/').to_owned()
    }
}

/// The log-level configuration init reads at boot
/// (`services/init/docs/bootstrap.md` § Log levels), on every architecture.
pub const LOG_LEVELS: DataEntry = DataEntry {
    install: "/config/init/log-levels.conf",
    source: "services/init/log-levels.conf",
};

/// Platform description tables that ship in a default-init bundle on one
/// architecture only: the text tables of the machines of that architecture,
/// which list the devices no firmware table describes. init forwards them to
/// devmgr with the driver modules; devmgr uses the one whose `oem_table_id`
/// equals the XSDT's (`services/devmgr/platform/`).
const ARCH_TABLES: &[(Arch, DataEntry)] = &[(
    Arch::Riscv64,
    DataEntry {
        install: "/config/devmgr/platform/qemu-virt.platform",
        source: "services/devmgr/platform/qemu-virt.platform",
    },
)];

/// The data entries of `arch`'s default-init bundle, in bundle order: the
/// architecture's platform tables, then the log-level configuration. The
/// sysroot installs each (`crate::sysroot::install_data_entries`).
pub fn data_entries(arch: Arch) -> Vec<DataEntry>
{
    ARCH_TABLES
        .iter()
        .filter(|(a, _)| *a == arch)
        .map(|(_, entry)| *entry)
        .chain([LOG_LEVELS])
        .collect()
}

/// The names of every entry of `arch`'s default-init bundle but `init`, in
/// bundle order: the objects signed with the boot-module role
/// (docs/signing.md § Signing).
pub fn boot_modules(arch: Arch) -> Vec<&'static str>
{
    let arch_modules = ARCH_MODULES
        .iter()
        .filter(|(a, _)| *a == arch)
        .map(|(_, install)| *install);
    MODULES
        .iter()
        .copied()
        .chain(arch_modules)
        .chain(data_entries(arch).into_iter().map(|entry| entry.install))
        .collect()
}

/// The harness of the staged bundle: [`Harness::Ktest`] when its `init`
/// entry is a copy of the installed `/tests/ktest` (the two bodies are
/// equal), [`Harness::Init`] otherwise, a missing ktest included. A pack signs
/// the sysroot for it, so ktest is signed `init` only in an image whose
/// bundle boots it.
///
/// # Errors
///
/// When the staged bundle cannot be read, does not parse, or holds no
/// `init` entry; when either object ends in a malformed trailer.
pub fn staged_harness(ctx: &BuildContext) -> Result<Harness>
{
    let path = ctx.sysroot_efi_seraph().join("bootstrap.bundle");
    let bundle = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let init = init_entry(&bundle).with_context(|| format!("reading {}", path.display()))?;
    let ktest_path = ctx.sysroot.join(Harness::Ktest.init_source());
    let ktest = match fs::read(&ktest_path)
    {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Harness::Init),
        Err(e) => return Err(e).with_context(|| format!("reading {}", ktest_path.display())),
    };
    if body_of(init)? == body_of(&ktest)?
    {
        Ok(Harness::Ktest)
    }
    else
    {
        Ok(Harness::Init)
    }
}

/// The object of `bundle`'s `init` entry.
fn init_entry(bundle: &[u8]) -> Result<&[u8]>
{
    let header =
        fmt::parse_header(bundle).map_err(|e| err!("the bundle does not parse ({e:?})"))?;
    let entry = (0..header.entry_count)
        .filter_map(|index| fmt::entry_at(bundle, index))
        .find(|entry| fmt::name_str(&entry.name) == fmt::INIT_ENTRY_NAME)
        .context("the bundle holds no `init` entry")?;
    let start = usize::try_from(entry.offset).context("entry offset past usize")?;
    let end = usize::try_from(entry.size)
        .ok()
        .and_then(|size| start.checked_add(size))
        .context("entry end past usize")?;
    bundle
        .get(start..end)
        .context("the `init` entry runs past the bundle")
}

/// Compose a bundle for the chosen harness and write it to
/// `sysroot/esp/EFI/seraph/bootstrap.bundle`, overwriting any existing
/// file. Each entry is copied from its installed file in the sysroot and
/// verified first as the bootloader will verify it ([`check_entry`]), under
/// the trust store the installed bootloader embeds; the sysroot must be
/// signed for `harness` already ([`crate::signing::sign_for_harness`]).
///
/// `Harness::Init` bundles `/services/init` as `init` plus every entry of
/// [`boot_modules`] for `arch`. `Harness::Ktest` bundles only
/// `/tests/ktest` as the `init` entry.
///
/// # Errors
///
/// When an installed file is missing or unreadable, when an entry does not
/// verify as the bootloader will, when the installed bootloaders hold no
/// common store, and on an I/O failure writing the bundle.
pub fn compose(ctx: &BuildContext, arch: Arch, harness: Harness) -> Result<()>
{
    let out_path = ctx.sysroot_efi_seraph().join("bootstrap.bundle");
    let store = installed_store(ctx, arch)?;
    let entries = entries(ctx, arch, harness)?;
    let bodies = bodies(&store, arch, &entries)?;

    let parent = out_path
        .parent()
        .context("compose-bundle: bundle path has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("compose-bundle: create {}", parent.display()))?;

    let entry_count =
        u32::try_from(entries.len()).context("compose-bundle: too many entries for u32")?;
    write_bundle(&out_path, entry_count, &bodies)?;

    step(&format!(
        "Bundle: {} ({} entries, harness={:?})",
        out_path.display(),
        entries.len(),
        harness
    ));
    Ok(())
}

/// The trust store every installed bootloader image of `arch` embeds: the
/// one the boot verifies the bundle under.
///
/// # Errors
///
/// When an image cannot be read, embeds no store or more than one, or the
/// images embed different stores.
fn installed_store(ctx: &BuildContext, arch: Arch) -> Result<Vec<u8>>
{
    let images = bootloader_images(ctx, arch);
    let first = &images[0];
    let bytes = fs::read(first).with_context(|| {
        format!(
            "reading the installed bootloader {} (run `cargo xtask build`)",
            first.display()
        )
    })?;
    let store = objsig::embed::find(&bytes)
        .map_err(|e| {
            err!(
                "the installed bootloader {} holds no trust store ({e:?}): run `cargo xtask build`",
                first.display()
            )
        })?
        .to_vec();
    check_installed_store(&images, &store)?;
    Ok(store)
}

/// One entry of a bundle: its name and the installed file it copies.
#[derive(Debug, PartialEq, Eq)]
struct Entry
{
    name: String,
    source: PathBuf,
}

impl Entry
{
    fn new(name: &str, source: PathBuf) -> Self
    {
        Self {
            name: name.to_owned(),
            source,
        }
    }

    /// The role the bootloader verifies the entry in: init for the `init`
    /// slot, boot module for every other entry.
    fn role(&self) -> Role
    {
        if self.name == INIT_SLOT
        {
            Role::Init
        }
        else
        {
            Role::BootModule
        }
    }
}

/// The entries of `harness`'s bundle for `arch`, in bundle order. Fails
/// naming the first installed file that does not exist.
fn entries(ctx: &BuildContext, arch: Arch, harness: Harness) -> Result<Vec<Entry>>
{
    let init_src = ctx.sysroot.join(harness.init_source());
    if !init_src.exists()
    {
        bail!(
            "compose-bundle: harness binary missing at {} (run `cargo xtask build` first)",
            init_src.display()
        );
    }

    let mut entries = vec![Entry::new(INIT_SLOT, init_src)];
    if harness == Harness::Init
    {
        for install in boot_modules(arch)
        {
            let p = ctx.sysroot.join(install.trim_start_matches('/'));
            if !p.exists()
            {
                bail!(
                    "compose-bundle: installed file missing at {} (run `cargo xtask build` first)",
                    p.display()
                );
            }
            entries.push(Entry::new(install, p));
        }
    }
    Ok(entries)
}

/// The `(name, object)` of each of `entries`: its installed file's bytes,
/// as they are, each checked as the bootloader will check it
/// ([`check_entry`]) under the encoded trust store `store`.
fn bodies(store: &[u8], arch: Arch, entries: &[Entry]) -> Result<Vec<(String, Vec<u8>)>>
{
    let store = TrustStore::parse(store)
        .map_err(|e| err!("compose-bundle: the installed trust store does not parse ({e:?})"))?;
    entries
        .iter()
        .map(|entry| {
            let bytes = fs::read(&entry.source)
                .with_context(|| format!("compose-bundle: read {}", entry.source.display()))?;
            check_entry(&store, arch, &entry.name, entry.role(), &bytes).with_context(|| {
                format!(
                    "compose-bundle: {} cannot be the bundle's {} entry (sign the sysroot for \
                     this harness: `cargo xtask build` or `cargo xtask compose-bundle`)",
                    entry.source.display(),
                    entry.name
                )
            })?;
            Ok((entry.name.clone(), bytes))
        })
        .collect()
}

/// Check `object` as the bootloader will check the bundle entry `name`
/// verified in `role`: a name that fits the entry header
/// ([`fmt::ENTRY_NAME_LEN`], `objsig::NAME_MAX`), `init` or an install path,
/// and an object that verifies under `store` in `role`, under `name`, for
/// `arch`.
fn check_entry(
    store: &TrustStore<'_>,
    arch: Arch,
    name: &str,
    role: Role,
    object: &[u8],
) -> Result<()>
{
    if name.len() > fmt::ENTRY_NAME_LEN
    {
        bail!(
            "the name {name} is longer than an entry name holds ({} bytes)",
            fmt::ENTRY_NAME_LEN
        );
    }
    if name != INIT_SLOT && !objsig::name_is_install_path(name.as_bytes())
    {
        bail!("the name {name} is neither `init` nor an install path");
    }
    let expect = Expectation {
        roles: RoleSet::of(&[role]),
        name: name.as_bytes(),
        arch: objsig_arch(arch),
    };
    objsig::verify(object, store, &expect)
        .map(|_| ())
        .map_err(|refusal| err!("it does not verify as {role:?} {name} ({refusal:?})"))
}

/// Write the bundle file of `(name, body)` entries: header, per-entry
/// headers, then bodies aligned to [`fmt::BODY_ALIGNMENT`].
fn write_bundle(out: &Path, entry_count: u32, entries: &[(String, Vec<u8>)]) -> Result<()>
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
    for (_, body) in entries
    {
        let size = u64::try_from(body.len()).context("compose-bundle: bundle size overflows")?;
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
            crate::error::bail!(
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
    for ((name, body), &offset) in entries.iter().zip(offsets.iter())
    {
        out_file
            .seek(SeekFrom::Start(offset))
            .context("compose-bundle: seek to body offset")?;
        out_file
            .write_all(body)
            .with_context(|| format!("compose-bundle: write body for {name}"))?;
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
    use crate::signing::testing::{scratch, signer, work_tree};
    use crate::signing::{Signer, sign_sysroot};
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

    // Defect caught: an entry name the bootloader refuses (not an install
    // path, or longer than the entry header holds), a data entry whose source
    // the repository does not hold, or the two architectures' lists naming
    // the other's IOMMU driver or platform table.
    #[test]
    fn every_entry_is_named_by_an_install_path_that_fits_the_entry_header()
    {
        let root = work_tree();
        for arch in [Arch::X86_64, Arch::Riscv64]
        {
            let names = boot_modules(arch);
            for name in &names
            {
                assert!(objsig::name_is_install_path(name.as_bytes()), "{name}");
                assert!(name.len() <= fmt::ENTRY_NAME_LEN, "{name}");
            }
            for entry in data_entries(arch)
            {
                assert!(names.contains(&entry.install), "{}", entry.install);
                assert!(root.join(entry.source).is_file(), "{}", entry.source);
                assert_eq!(entry.relative(), &entry.install[1..]);
            }
        }
        let x86 = boot_modules(Arch::X86_64);
        let riscv = boot_modules(Arch::Riscv64);
        assert!(x86.contains(&"/services/drivers/iommu-vtd"));
        assert!(!x86.contains(&"/services/drivers/iommu-riscv"));
        assert!(riscv.contains(&"/services/drivers/iommu-riscv"));
        assert!(riscv.contains(&"/config/devmgr/platform/qemu-virt.platform"));
        assert!(!x86.contains(&"/config/devmgr/platform/qemu-virt.platform"));
        assert!(x86.contains(&LOG_LEVELS.install) && riscv.contains(&LOG_LEVELS.install));
    }

    /// A build context in a scratch directory whose sysroot installs every
    /// object of `arch`'s default-init bundle, ktest, and bootloader images
    /// embedding the trust store of a throwaway identity; the sysroot is not
    /// signed. Returns the scratch root, the context and the signer.
    fn fixture(tag: &str, arch: Arch) -> (PathBuf, BuildContext, Signer)
    {
        let root = scratch(tag);
        let ctx = BuildContext {
            root: root.clone(),
            sysroot: root.join("sysroot"),
            target_dir: root.join("target"),
        };
        let signer = signer(&root.join("keys"), arch);
        let data: Vec<&str> = data_entries(arch)
            .iter()
            .map(|entry| entry.install)
            .collect();
        let installs = ["/services/init", "/tests/ktest"]
            .into_iter()
            .chain(boot_modules(arch));
        for install in installs
        {
            let path = ctx.sysroot.join(&install[1..]);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let body: Vec<u8> = if data.contains(&install)
            {
                format!("data of {install}\n").into_bytes()
            }
            else
            {
                [b"\x7fELF ".as_slice(), install.as_bytes()].concat()
            };
            fs::write(&path, body).unwrap();
        }
        let mut image = b"bootloader code".to_vec();
        image.extend_from_slice(&objsig::embed::MARKER);
        let len = u32::try_from(signer.store().len()).unwrap();
        image.extend_from_slice(&len.to_le_bytes());
        image.extend_from_slice(signer.store());
        image.extend_from_slice(b"more code");
        for path in bootloader_images(&ctx, arch)
        {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, &image).unwrap();
        }
        (root, ctx, signer)
    }

    /// The `(name, object)` of every entry of the staged bundle of `ctx`.
    fn staged(ctx: &BuildContext) -> Vec<(String, Vec<u8>)>
    {
        let bundle = fs::read(ctx.sysroot_efi_seraph().join("bootstrap.bundle")).unwrap();
        let header = fmt::parse_header(&bundle).unwrap();
        (0..header.entry_count)
            .map(|index| {
                let entry = fmt::entry_at(&bundle, index).unwrap();
                let start = usize::try_from(entry.offset).unwrap();
                let end = start + usize::try_from(entry.size).unwrap();
                (
                    String::from_utf8(fmt::name_str(&entry.name).to_vec()).unwrap(),
                    bundle[start..end].to_vec(),
                )
            })
            .collect()
    }

    // Defect caught: an entry that is not its installed file byte for byte
    // (a composer that signs, re-signs or renames), an entry missing from the
    // default bundle or out of its order, or a ktest bundle that carries
    // modules.
    #[test]
    fn a_bundle_copies_each_installed_object_under_its_install_path()
    {
        let arch = Arch::Riscv64;
        let (root, ctx, signer) = fixture("copies", arch);
        sign_sysroot(&ctx, &signer, arch, Harness::Init).unwrap();
        compose(&ctx, arch, Harness::Init).unwrap();
        let names: Vec<&str> = std::iter::once(INIT_SLOT)
            .chain(boot_modules(arch))
            .collect();
        let entries = staged(&ctx);
        assert_eq!(
            entries
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            names
        );
        for (name, object) in &entries
        {
            let install = if name == INIT_SLOT
            {
                "services/init"
            }
            else
            {
                &name[1..]
            };
            assert_eq!(
                *object,
                fs::read(ctx.sysroot.join(install)).unwrap(),
                "{name}"
            );
        }
        assert_eq!(staged_harness(&ctx).unwrap(), Harness::Init);

        sign_sysroot(&ctx, &signer, arch, Harness::Ktest).unwrap();
        compose(&ctx, arch, Harness::Ktest).unwrap();
        let entries = staged(&ctx);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, INIT_SLOT);
        assert_eq!(
            entries[0].1,
            fs::read(ctx.sysroot.join("tests/ktest")).unwrap()
        );
        assert_eq!(staged_harness(&ctx).unwrap(), Harness::Ktest);
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: a bundle written with an entry the bootloader will
    // refuse, so the boot stops where the build could have: an object left
    // unsigned, one signed without the role of its slot (an image the bundle
    // names signed without the boot-module role, ktest in the `init` slot of
    // a sysroot not signed for the ktest harness), one signed by a key the
    // installed bootloader does not trust, or one whose name is not one the
    // bootloader accepts.
    #[test]
    fn an_entry_the_bootloader_would_refuse_fails_the_compose()
    {
        let arch = Arch::X86_64;
        let (root, ctx, signer) = fixture("refuses", arch);
        // Unsigned.
        compose(&ctx, arch, Harness::Init).unwrap_err();
        sign_sysroot(&ctx, &signer, arch, Harness::Init).unwrap();
        compose(&ctx, arch, Harness::Init).unwrap();
        // ktest is signed for the ktest harness only.
        compose(&ctx, arch, Harness::Ktest).unwrap_err();

        // An entry without the boot-module role.
        let vfsd = ctx.sysroot.join("services/vfsd");
        let good = fs::read(&vfsd).unwrap();
        signer
            .sign_file(&vfsd, RoleSet::of(&[Role::Service]), "/services/vfsd")
            .unwrap();
        compose(&ctx, arch, Harness::Init).unwrap_err();
        fs::write(&vfsd, &good).unwrap();
        compose(&ctx, arch, Harness::Init).unwrap();

        // An entry signed by a key the installed bootloader does not trust.
        let theirs = Signer::new(
            &crate::signing::testing::config(&root.join("theirs")),
            &work_tree(),
            arch,
            &mut crate::signing::testing::counter(50),
        )
        .unwrap();
        theirs
            .sign_file(
                &vfsd,
                RoleSet::of(&[Role::Service, Role::BootModule]),
                "/services/vfsd",
            )
            .unwrap();
        compose(&ctx, arch, Harness::Init).unwrap_err();
        fs::write(&vfsd, &good).unwrap();

        // Names the bootloader refuses.
        let store = TrustStore::parse(signer.store()).unwrap();
        let long = format!("/services/{}", "x".repeat(fmt::ENTRY_NAME_LEN));
        let object = signer
            .sign(
                b"\x7fELF x",
                RoleSet::of(&[Role::BootModule]),
                "/services/x",
            )
            .unwrap();
        check_entry(&store, arch, "/services/x", Role::BootModule, &object).unwrap();
        check_entry(&store, arch, &long, Role::BootModule, &object).unwrap_err();
        check_entry(&store, arch, "services/x", Role::BootModule, &object).unwrap_err();
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: a pack that signs ktest as init in an image whose bundle
    // does not boot it, or does not when it does.
    #[test]
    fn the_staged_harness_is_ktest_only_when_its_init_entry_is_ktest()
    {
        let arch = Arch::Riscv64;
        let (root, ctx, signer) = fixture("harness", arch);
        sign_sysroot(&ctx, &signer, arch, Harness::Ktest).unwrap();
        compose(&ctx, arch, Harness::Ktest).unwrap();
        assert_eq!(staged_harness(&ctx).unwrap(), Harness::Ktest);
        // The init entry's body decides, not its trailer: ktest re-signed for
        // the init harness is still the ktest bundle's init.
        sign_sysroot(&ctx, &signer, arch, Harness::Init).unwrap();
        assert_eq!(staged_harness(&ctx).unwrap(), Harness::Ktest);
        compose(&ctx, arch, Harness::Init).unwrap();
        assert_eq!(staged_harness(&ctx).unwrap(), Harness::Init);
        // A sysroot without ktest packs the init harness.
        fs::remove_file(ctx.sysroot.join("tests/ktest")).unwrap();
        assert_eq!(staged_harness(&ctx).unwrap(), Harness::Init);
        let _ = fs::remove_dir_all(&root);
    }

    /// Two-entry round trip: write a bundle of two tiny bodies,
    /// parse it back via the shared format reader, and verify each
    /// entry's name, offset alignment, and body bytes.
    #[test]
    fn write_bundle_round_trip()
    {
        let tmp = scratch("bundle-rt");
        let out = tmp.join("bundle.bin");
        let entries = vec![
            ("init".to_owned(), b"alpha".to_vec()),
            ("/services/svc".to_owned(), b"beta--".to_vec()),
        ];
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
        assert_eq!(fmt::name_str(&e1.name), b"/services/svc");
        assert_eq!(e1.size, 6);
        assert!(e1.offset.is_multiple_of(fmt::BODY_ALIGNMENT));
        let body1 = &buf
            [usize::try_from(e1.offset).unwrap()..usize::try_from(e1.offset + e1.size).unwrap()];
        assert_eq!(body1, b"beta--");

        let _ = fs::remove_dir_all(&tmp);
    }
}
