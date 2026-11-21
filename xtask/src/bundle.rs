// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/bundle.rs

//! Compose the bootloader bundle, the ESP's `EFI/seraph/bootstrap.bundle`,
//! from the installed files of the sysroot that the bundle list of its
//! harness names (docs/boot-media.md § The ESP). The format is defined by
//! [`boot_protocol::bundle`] and shared with the bootloader consumer side;
//! this module is the only producer in the tree.
//!
//! Each [`Harness`] has a bundle list in configuration, installed under
//! `/config/bundle/` from `rootfs/config/bundle/` ([`list_path`]): its
//! `init` line names the object copied into the `init` slot, and every other
//! line an entry, by its install path, which is also the entry's name
//! ([`parse_list`]). xtask holds no list of its own.
//!
//! Every entry is its installed file byte for byte. The composer signs
//! nothing and reads no key: the sysroot is signed first
//! ([`crate::signing::sign_for_harness`]), and the composer verifies each
//! entry as the bootloader will, under the trust store the installed
//! bootloader embeds, before it writes the bundle.

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::argparse::ValueEnum as _;
use crate::error::{Context, Result, bail, err};
use boot_protocol::bundle as fmt;
use objsig::{Expectation, Role, RoleSet, TrustStore};

use crate::arch::Arch;
use crate::context::Context as BuildContext;
use crate::signing::{INIT_SLOT, installed_store, objsig_arch};
use crate::util::step;

crate::argparse::value_enum! {
    /// Which harness's bundle list composes the bundle, and so which object
    /// is its `"init"` entry.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Harness
    {
        /// The userspace init, `/services/init`, with every module the
        /// system needs to bootstrap userspace (`init.<arch>.list`).
        #[value(name = "init")]
        Init,
        /// The kernel-test harness, `/tests/ktest`, as the `"init"` entry
        /// alone: ktest is monolithic and spawns no module (`ktest.list`).
        #[value(name = "ktest")]
        Ktest,
    }
}

/// The sysroot-relative directory the bundle lists are installed in, and the
/// `rootfs/`-relative one they are installed from.
pub const LIST_DIR: &str = "config/bundle";

/// A bundle list: the objects of one harness's bundle, by install path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleList
{
    /// The install path of the object copied into the `init` slot.
    pub init: String,
    /// The install path of every other entry, in bundle order, each also the
    /// name of its entry.
    pub entries: Vec<String>,
}

/// The installed bundle list of `harness` for `arch` ([`list_in`] of the
/// sysroot's `config/bundle/`).
///
/// # Errors
///
/// Those of [`list_in`].
pub fn list_path(ctx: &BuildContext, arch: Arch, harness: Harness) -> Result<PathBuf>
{
    list_in(&ctx.sysroot.join(LIST_DIR), arch, harness)
}

/// The bundle list of `harness` for `arch` in `dir` ([`list_name`]).
///
/// # Errors
///
/// When `dir` holds neither of the names, or both, so the list is not one
/// file.
fn list_in(dir: &Path, arch: Arch, harness: Harness) -> Result<PathBuf>
{
    let name = list_name(arch, harness, |name| dir.join(name).is_file()).with_context(|| {
        format!(
            "in {} (run `cargo xtask build` or `cargo xtask mkdisk`)",
            dir.display()
        )
    })?;
    Ok(dir.join(name))
}

/// The file name of the bundle list of `harness` for `arch` in a directory
/// that holds a file of a name when `holds` says so:
/// `<harness>.<arch>.list` where the architectures' lists differ,
/// `<harness>.list` where they do not.
///
/// # Errors
///
/// When the directory holds neither, or both, so the list is not one file.
pub fn list_name(arch: Arch, harness: Harness, holds: impl Fn(&str) -> bool) -> Result<String>
{
    let name = harness.name();
    let own = format!("{name}.{arch}.list");
    let shared = format!("{name}.list");
    match (holds(&own), holds(&shared))
    {
        (true, false) => Ok(own),
        (false, true) => Ok(shared),
        (true, true) =>
        {
            bail!(
                "both {own} and {shared} are installed: a harness has one bundle list for an architecture"
            )
        }
        (false, false) =>
        {
            bail!(
                "no bundle list of the {name} harness for {arch}: neither {own} nor {shared} is installed"
            )
        }
    }
}

/// The installed bundle list of `harness` for `arch` ([`list_path`]),
/// parsed ([`parse_list`]).
///
/// # Errors
///
/// Those of [`list_path`] and [`parse_list`]; when the list cannot be read.
pub fn read_list(ctx: &BuildContext, arch: Arch, harness: Harness) -> Result<BundleList>
{
    let path = list_path(ctx, arch, harness)?;
    let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    parse_list(&text).with_context(|| format!("parsing {}", path.display()))
}

/// The bundle list `text` holds. A line is blank, a comment (`#` first),
/// `init <path>`, naming the object of the `init` slot, or `<path>`, naming
/// an entry. Every path is an install path short enough to name an entry
/// ([`fmt::ENTRY_NAME_LEN`]).
///
/// # Errors
///
/// When a line is none of these, a path is not an install path or is longer
/// than an entry name holds, an object is named twice, or the list has no
/// `init` line or more than one.
pub fn parse_list(text: &str) -> Result<BundleList>
{
    let mut init: Option<String> = None;
    let mut entries: Vec<String> = Vec::new();
    for (index, raw) in text.lines().enumerate()
    {
        let number = index.saturating_add(1);
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#')
        {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        let (slot, path) = match words.as_slice()
        {
            [keyword, path] if *keyword == INIT_SLOT => (true, *path),
            [path] => (false, *path),
            _ => bail!("line {number}: {line:?} is neither `init <path>` nor an install path"),
        };
        if !objsig::name_is_install_path(path.as_bytes())
        {
            bail!("line {number}: {path} is not an install path");
        }
        if path.len() > fmt::ENTRY_NAME_LEN
        {
            bail!(
                "line {number}: {path} is longer than an entry name holds ({} bytes)",
                fmt::ENTRY_NAME_LEN
            );
        }
        if init.as_deref() == Some(path) || entries.iter().any(|entry| entry == path)
        {
            bail!("line {number}: {path} is named twice");
        }
        if !slot
        {
            entries.push(path.to_owned());
        }
        else if init.is_some()
        {
            bail!("line {number}: a second `init` line");
        }
        else
        {
            init = Some(path.to_owned());
        }
    }
    let init = init.context("the list has no `init` line")?;
    Ok(BundleList { init, entries })
}

/// The install path of every entry but `init` that a bundle list of `arch`
/// names, over every harness, each once, in list order: the objects signed
/// with the boot-module role (docs/signing.md § Signing).
///
/// # Errors
///
/// Those of [`read_list`], for any harness.
pub fn boot_modules(ctx: &BuildContext, arch: Arch) -> Result<Vec<String>>
{
    let mut names: Vec<String> = Vec::new();
    for harness in Harness::VARIANTS
    {
        for entry in read_list(ctx, arch, *harness)?.entries
        {
            if !names.contains(&entry)
            {
                names.push(entry);
            }
        }
    }
    Ok(names)
}

/// The path of the bundle from the ESP's root.
pub const ESP_PATH: &str = "/EFI/seraph/bootstrap.bundle";

/// The path of the bundle on the ESP the sysroot stages,
/// `sysroot/esp/EFI/seraph/bootstrap.bundle` ([`ESP_PATH`]).
pub fn esp_path(ctx: &BuildContext) -> PathBuf
{
    ctx.sysroot_esp().join(ESP_PATH.trim_start_matches('/'))
}

/// Compose the bundle of `harness` for `arch` and write it to `out`,
/// overwriting any existing file. Each entry is copied from the installed
/// file its bundle list names ([`read_list`]) and verified first as the
/// bootloader will verify it ([`check_entry`]), under the trust store the
/// installed bootloader embeds; the sysroot must be signed for `harness`
/// already ([`crate::signing::sign_for_harness`]).
///
/// # Errors
///
/// Those of [`read_list`]; when an installed file is missing or unreadable,
/// when an entry does not verify as the bootloader will, when the installed
/// bootloader holds no trust store, and on an I/O failure writing the bundle.
pub fn compose(ctx: &BuildContext, arch: Arch, harness: Harness, out: &Path) -> Result<()>
{
    let list = read_list(ctx, arch, harness)?;
    let store = installed_store(ctx)?;
    let entries = entries(ctx, &list)?;
    let bodies = bodies(&store, arch, &entries)?;

    let parent = out.parent().context("bundle: bundle path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("bundle: create {}", parent.display()))?;

    let entry_count = u32::try_from(entries.len()).context("bundle: too many entries for u32")?;
    write_bundle(out, entry_count, &bodies)?;

    step(&format!(
        "Bundle: {} ({} entries, harness={})",
        out.display(),
        entries.len(),
        harness.name()
    ));
    Ok(())
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

/// The entries of `list`'s bundle, in bundle order, `init` first. Fails
/// naming the first installed file that does not exist.
fn entries(ctx: &BuildContext, list: &BundleList) -> Result<Vec<Entry>>
{
    let named = std::iter::once((INIT_SLOT, &list.init))
        .chain(list.entries.iter().map(|path| (path.as_str(), path)));
    let mut entries = Vec::new();
    for (name, install) in named
    {
        let source = ctx.sysroot.join(install.trim_start_matches('/'));
        if !source.is_file()
        {
            bail!(
                "bundle: installed file missing at {} (run `cargo xtask build` first)",
                source.display()
            );
        }
        entries.push(Entry {
            name: name.to_owned(),
            source,
        });
    }
    Ok(entries)
}

/// The `(name, object)` of each of `entries`: its installed file's bytes,
/// as they are, each checked as the bootloader will check it
/// ([`check_entry`]) under the encoded trust store `store`.
fn bodies(store: &[u8], arch: Arch, entries: &[Entry]) -> Result<Vec<(String, Vec<u8>)>>
{
    let store = TrustStore::parse(store)
        .map_err(|e| err!("bundle: the installed trust store does not parse ({e:?})"))?;
    entries
        .iter()
        .map(|entry| {
            let bytes = fs::read(&entry.source)
                .with_context(|| format!("bundle: read {}", entry.source.display()))?;
            check_entry(&store, arch, &entry.name, entry.role(), &bytes).with_context(|| {
                format!(
                    "bundle: {} cannot be the bundle's {} entry (sign the sysroot for \
                     this harness: `cargo xtask build` or `cargo xtask mkdisk --harness`)",
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
pub(crate) fn write_bundle(
    out: &Path,
    entry_count: u32,
    entries: &[(String, Vec<u8>)],
) -> Result<()>
{
    let mut out_file =
        fs::File::create(out).with_context(|| format!("bundle: create {}", out.display()))?;

    out_file
        .write_all(&fmt::MAGIC)
        .context("bundle: write magic")?;
    out_file
        .write_all(&fmt::VERSION.to_le_bytes())
        .context("bundle: write version")?;
    out_file
        .write_all(&entry_count.to_le_bytes())
        .context("bundle: write entry_count")?;

    // Compute body offsets up front so the entry header table can be
    // written before the bodies themselves.
    let header_table_len = entries
        .len()
        .checked_mul(fmt::ENTRY_HEADER_SIZE)
        .and_then(|len| u64::try_from(len).ok())
        .context("bundle: entry header table size overflows")?;
    let mut offsets: Vec<u64> = Vec::with_capacity(entries.len());
    let mut cursor = (fmt::HEADER_SIZE as u64)
        .checked_add(header_table_len)
        .context("bundle: bundle size overflows")?;
    let mut sizes: Vec<u64> = Vec::with_capacity(entries.len());
    for (_, body) in entries
    {
        let size = u64::try_from(body.len()).context("bundle: bundle size overflows")?;
        cursor = align_up(cursor, fmt::BODY_ALIGNMENT).context("bundle: bundle size overflows")?;
        offsets.push(cursor);
        sizes.push(size);
        cursor = cursor
            .checked_add(size)
            .context("bundle: bundle size overflows")?;
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
                "bundle: entry name `{name}` exceeds {} bytes",
                fmt::ENTRY_NAME_LEN
            );
        };
        name_dst.copy_from_slice(nb);
        out_file
            .write_all(&name_buf)
            .context("bundle: write entry name")?;
        out_file
            .write_all(&offset.to_le_bytes())
            .context("bundle: write entry offset")?;
        out_file
            .write_all(&size.to_le_bytes())
            .context("bundle: write entry size")?;
    }

    // Bodies (aligned).
    for ((name, body), &offset) in entries.iter().zip(offsets.iter())
    {
        out_file
            .seek(SeekFrom::Start(offset))
            .context("bundle: seek to body offset")?;
        out_file
            .write_all(body)
            .with_context(|| format!("bundle: write body for {name}"))?;
    }

    out_file.sync_all().context("bundle: sync bundle file")?;
    Ok(())
}

/// The `(name, body)` of every entry of the bundle `bundle`, in bundle order,
/// read with the bootloader's parser ([`fmt::parse_header`]).
///
/// # Errors
///
/// When the bundle does not parse, or an entry's name is not UTF-8.
pub fn parse_entries(bundle: &[u8]) -> Result<Vec<(String, &[u8])>>
{
    let header =
        fmt::parse_header(bundle).map_err(|refusal| err!("it does not parse ({refusal:?})"))?;
    (0..header.entry_count)
        .map(|index| {
            let entry =
                fmt::entry_at(bundle, index).with_context(|| format!("it has no entry {index}"))?;
            let name = std::str::from_utf8(fmt::name_str(&entry.name))
                .with_context(|| format!("the name of its entry {index} is not UTF-8"))?;
            let body = usize::try_from(entry.offset)
                .ok()
                .zip(usize::try_from(entry.size).ok())
                .and_then(|(start, size)| Some(start..start.checked_add(size)?))
                .and_then(|range| bundle.get(range))
                .with_context(|| format!("the body of its entry {name} lies outside it"))?;
            Ok((name.to_owned(), body))
        })
        .collect()
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
    use crate::signing::testing::{install_lists, scratch, signer, work_tree};
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

    /// The bundle list of `harness` for `arch` that `rootfs/` holds.
    fn repository_list(arch: Arch, harness: Harness) -> BundleList
    {
        let dir = work_tree().join("rootfs").join(LIST_DIR);
        let path = list_in(&dir, arch, harness).unwrap();
        parse_list(&fs::read_to_string(path).unwrap()).unwrap()
    }

    // Defect caught: a list that does not parse, names a file no build
    // installs for its architecture (a mistyped path, the other
    // architecture's IOMMU driver), names an object outside the bootstrap
    // closure (a console driver, a platform description table), or puts
    // another object than the harness's in the `init` slot.
    #[test]
    fn every_list_names_files_the_build_installs_for_its_architecture()
    {
        let root = work_tree();
        for arch in [Arch::X86_64, Arch::Riscv64]
        {
            let mut installed = crate::commands::build::install_names(arch);
            installed.extend(
                crate::sysroot::data_files(arch)
                    .iter()
                    .map(|file| file.install.to_owned()),
            );
            for harness in Harness::VARIANTS
            {
                let list = repository_list(arch, *harness);
                for path in std::iter::once(&list.init).chain(&list.entries)
                {
                    let in_rootfs = root.join("rootfs").join(&path[1..]).is_file();
                    assert!(
                        in_rootfs || installed.contains(path),
                        "{arch} {}: {path}",
                        harness.name()
                    );
                }
            }
            assert_eq!(repository_list(arch, Harness::Init).init, "/services/init");
            let ktest = repository_list(arch, Harness::Ktest);
            assert_eq!(ktest.init, "/tests/ktest");
            assert_eq!(ktest.entries, Vec::<String>::new());
        }
        let x86 = repository_list(Arch::X86_64, Harness::Init).entries;
        let riscv = repository_list(Arch::Riscv64, Harness::Init).entries;
        let has = |list: &[String], path: &str| list.iter().any(|entry| entry == path);
        assert!(has(&x86, "/services/drivers/iommu-vtd"));
        assert!(has(&riscv, "/services/drivers/iommu-riscv"));
        for list in [&x86, &riscv]
        {
            assert!(has(list, crate::sysroot::LOG_LEVELS.install));
            // The bootstrap closure (docs/boot-media.md): the consoles and
            // the platform description tables load from the root filesystem.
            for outside in [
                "/services/drivers/serial",
                "/services/drivers/framebuffer",
                "/config/devmgr/platform/qemu-virt.platform",
            ]
            {
                assert!(!has(list, outside), "{outside}");
            }
        }
    }

    // Defect caught: a list line read as another than it is (a comment as an
    // entry, a second path dropped), or a list the bootloader would refuse a
    // bundle of (a name that is not an install path or does not fit the entry
    // header, an object twice, no object or two in the `init` slot).
    #[test]
    fn a_list_is_read_line_by_line_and_a_malformed_one_refused()
    {
        let list = parse_list(
            "# comment\n\n  init /services/init  \n/services/a\n\t/config/b.conf\n# init /x\n",
        )
        .unwrap();
        assert_eq!(list.init, "/services/init");
        assert_eq!(list.entries, ["/services/a", "/config/b.conf"]);
        let long = format!("/services/{}", "x".repeat(fmt::ENTRY_NAME_LEN));
        for text in [
            "/services/a\n",
            "init /services/init\ninit /tests/ktest\n",
            "init /services/init\n/services/a /services/b\n",
            "init /services/init\nkernel /services/a\n",
            "init services/init\n",
            "init /services/init\n/services/a\n/services/a\n",
            "init /services/init\n/services/init\n",
            "init /services/init\n/services/../a\n",
            &format!("init /services/init\n{long}\n"),
        ]
        {
            parse_list(text).expect_err(text);
        }
    }

    // Defect caught: a harness whose list is taken from the other
    // architecture's file, or one with two lists that picks either silently.
    #[test]
    fn a_harness_has_one_list_for_an_architecture()
    {
        let dir = scratch("lists");
        let own = dir.join("init.riscv64.list");
        let shared = dir.join("init.list");
        list_in(&dir, Arch::Riscv64, Harness::Init).unwrap_err();
        fs::write(&own, "").unwrap();
        assert_eq!(list_in(&dir, Arch::Riscv64, Harness::Init).unwrap(), own);
        list_in(&dir, Arch::X86_64, Harness::Init).unwrap_err();
        fs::write(&shared, "").unwrap();
        list_in(&dir, Arch::Riscv64, Harness::Init).unwrap_err();
        assert_eq!(list_in(&dir, Arch::X86_64, Harness::Init).unwrap(), shared);
        list_in(&dir, Arch::X86_64, Harness::Ktest).unwrap_err();
        let _ = fs::remove_dir_all(&dir);
    }

    /// A build context in a scratch directory whose sysroot installs the
    /// repository's bundle lists, every file they name for `arch`, and a
    /// bootloader embedding the trust store of a throwaway identity; the
    /// sysroot is not signed. Returns the scratch root, the context and the
    /// signer.
    fn fixture(tag: &str, arch: Arch) -> (PathBuf, BuildContext, Signer)
    {
        let root = scratch(tag);
        let ctx = BuildContext {
            root: root.clone(),
            sysroot: root.join("sysroot"),
            target_dir: root.join("target"),
        };
        let signer = signer(&root.join("keys"), arch);
        install_lists(&ctx);
        let mut installs = Vec::new();
        for harness in Harness::VARIANTS
        {
            let list = read_list(&ctx, arch, *harness).unwrap();
            installs.push(list.init);
            installs.extend(list.entries);
        }
        for install in installs
        {
            let path = ctx.sysroot.join(&install[1..]);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let body: Vec<u8> = if install.starts_with("/config/")
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
        let bootloader = ctx.installed_bootloader();
        fs::create_dir_all(bootloader.parent().unwrap()).unwrap();
        fs::write(&bootloader, &image).unwrap();
        (root, ctx, signer)
    }

    /// The `(name, object)` of every entry of the bundle at `path`.
    fn read_entries(path: &Path) -> Vec<(String, Vec<u8>)>
    {
        let bundle = fs::read(path).unwrap();
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
    // (a composer that signs, re-signs or renames), an entry the list names
    // missing from the bundle or out of its order, a ktest bundle that
    // carries modules, or an installed file the composer changes.
    #[test]
    fn a_bundle_copies_each_file_its_list_names_under_its_install_path()
    {
        let arch = Arch::Riscv64;
        let (root, ctx, signer) = fixture("copies", arch);
        let out = esp_path(&ctx);
        sign_sysroot(&ctx, &signer, arch, Harness::Init).unwrap();
        let list = read_list(&ctx, arch, Harness::Init).unwrap();
        let before: Vec<Vec<u8>> = std::iter::once(&list.init)
            .chain(&list.entries)
            .map(|install| fs::read(ctx.sysroot.join(&install[1..])).unwrap())
            .collect();
        compose(&ctx, arch, Harness::Init, &out).unwrap();
        let entries = read_entries(&out);
        let names: Vec<&str> = std::iter::once(INIT_SLOT)
            .chain(list.entries.iter().map(String::as_str))
            .collect();
        assert_eq!(
            entries
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            names
        );
        for ((name, object), installed) in entries.iter().zip(&before)
        {
            assert_eq!(object, installed, "{name}");
        }
        assert_eq!(boot_modules(&ctx, arch).unwrap(), list.entries);

        sign_sysroot(&ctx, &signer, arch, Harness::Ktest).unwrap();
        let other = root.join("elsewhere").join("bootstrap.bundle");
        compose(&ctx, arch, Harness::Ktest, &other).unwrap();
        let entries = read_entries(&other);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, INIT_SLOT);
        assert_eq!(
            entries[0].1,
            fs::read(ctx.sysroot.join("tests/ktest")).unwrap()
        );
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: a bundle written with an entry the bootloader will
    // refuse, so the boot stops where the build could have: an object left
    // unsigned or not installed, one signed without the role of its slot (an
    // image the bundle names signed without the boot-module role, ktest in
    // the `init` slot of a sysroot not signed for the ktest harness), one
    // signed by a key the installed bootloader does not trust, or one whose
    // name is not one the bootloader accepts.
    #[test]
    fn an_entry_the_bootloader_would_refuse_fails_the_compose()
    {
        let arch = Arch::X86_64;
        let (root, ctx, signer) = fixture("refuses", arch);
        let out = esp_path(&ctx);
        // Unsigned.
        compose(&ctx, arch, Harness::Init, &out).unwrap_err();
        sign_sysroot(&ctx, &signer, arch, Harness::Init).unwrap();
        compose(&ctx, arch, Harness::Init, &out).unwrap();
        // ktest is signed for the ktest harness only.
        compose(&ctx, arch, Harness::Ktest, &out).unwrap_err();

        // An entry without the boot-module role.
        let vfsd = ctx.sysroot.join("services/vfsd");
        let good = fs::read(&vfsd).unwrap();
        signer
            .sign_file(&vfsd, RoleSet::of(&[Role::Service]), "/services/vfsd")
            .unwrap();
        compose(&ctx, arch, Harness::Init, &out).unwrap_err();
        fs::write(&vfsd, &good).unwrap();
        compose(&ctx, arch, Harness::Init, &out).unwrap();

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
        compose(&ctx, arch, Harness::Init, &out).unwrap_err();
        fs::write(&vfsd, &good).unwrap();
        compose(&ctx, arch, Harness::Init, &out).unwrap();

        // An entry its list names that the sysroot does not install.
        fs::remove_file(&vfsd).unwrap();
        compose(&ctx, arch, Harness::Init, &out).unwrap_err();
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
