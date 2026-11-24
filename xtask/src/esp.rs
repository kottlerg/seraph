// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/esp.rs

//! Compose the ESP the sysroot stages (`sysroot/esp/`) from installed files
//! (docs/boot-media.md § The ESP): the bootloader at `\EFI\seraph\boot.efi`
//! and at the firmware's removable-media default, the kernel at
//! `\EFI\seraph\kernel`, each a byte copy of its installed file under
//! `/boot/`, and the bundle ([`crate::bundle::compose`]). Every pack composes
//! it as its last step before it writes the images
//! (`crate::disk::create_disk_image`), and checks, once it has written it,
//! that every object on it equals the installed file it copies ([`check`]),
//! so the ESP of every image equals the installed files it derives from.
//! The pack then makes the same check of the image it wrote, its ESP against
//! the installed files, those on its root partition or, for the kernel layer's
//! image, the sysroot's (`crate::image_check`).
//!
//! Composing signs nothing and reads no key: the sysroot is signed first
//! (`crate::signing::sign_for_harness`), and the composer checks what it
//! copies as the bootloader will, under the trust store the installed
//! bootloader embeds.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use objsig::{Expectation, Role, RoleSet, TrustStore};

use crate::arch::Arch;
use crate::argparse::ValueEnum as _;
use crate::bundle::{self, BundleList, Harness};
use crate::context::Context as BuildContext;
use crate::error::{Context as _, Result, bail, err};
use crate::signing::{INIT_SLOT, installed_store, objsig_arch};

/// The name the kernel is signed under (docs/signing.md § Signing).
const KERNEL_NAME: &str = "kernel";

/// The install path of the bootloader.
const BOOTLOADER_INSTALL: &str = "/boot/boot.efi";

/// The install path of the kernel.
const KERNEL_INSTALL: &str = "/boot/kernel";

/// The directory, from the ESP's root, of the bootloader's own copy, the
/// kernel, the bundle and the bootloader's presence-only knobs.
const VENDOR_DIR: &str = "/EFI/seraph";

/// The paths, from the ESP's root, of the ESP copies of the installed
/// bootloader: the one `\EFI\seraph\boot.efi` names and the removable-media
/// default the firmware boots.
fn bootloader_paths(arch: Arch) -> [String; 2]
{
    [
        format!("{VENDOR_DIR}/boot.efi"),
        format!("/EFI/BOOT/{}", arch.boot_efi_filename()),
    ]
}

/// The path of the kernel's copy from the ESP's root.
fn kernel_path() -> String
{
    format!("{VENDOR_DIR}/{KERNEL_NAME}")
}

crate::argparse::value_enum! {
    /// A presence-only bootloader knob: an empty file in the ESP's
    /// `\EFI\seraph\`, read by the next boot of an image packed with it
    /// (docs/boot-media.md § The ESP).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Knob
    {
        /// `\EFI\seraph\nokaslr`: the bootloader boots the kernel at its
        /// deterministic (un-randomized) layout.
        #[value(name = "nokaslr")]
        NoKaslr,
        /// `\EFI\seraph\mapredo`: the bootloader redoes the first attempt of its
        /// steps 6 and 7 whatever its memory map's size.
        #[value(name = "mapredo")]
        MapRedo,
    }
}

/// The path of `knob` in the sysroot's ESP.
fn knob_path(ctx: &BuildContext, knob: Knob) -> PathBuf
{
    ctx.sysroot_efi_seraph().join(knob.name())
}

/// Stage `knob` in the sysroot's ESP so the next pack's image carries it.
/// Idempotent.
///
/// # Errors
///
/// On an I/O failure.
pub fn stage_knob(ctx: &BuildContext, knob: Knob) -> Result<()>
{
    let path = knob_path(ctx, knob);
    if let Some(dir) = path.parent()
    {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    fs::write(&path, b"").with_context(|| format!("writing {}", path.display()))
}

/// Remove `knob` from the sysroot's ESP so the next pack's image lacks it.
/// Idempotent: an absent knob is left absent.
///
/// # Errors
///
/// On an I/O failure other than the knob's absence.
pub fn remove_knob(ctx: &BuildContext, knob: Knob) -> Result<()>
{
    let path = knob_path(ctx, knob);
    match fs::remove_file(&path)
    {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

/// Stage each of `knobs` and remove every other knob, so the next pack's
/// image carries exactly `knobs`.
///
/// # Errors
///
/// As [`stage_knob`] and [`remove_knob`].
pub fn set_knobs(ctx: &BuildContext, knobs: &[Knob]) -> Result<()>
{
    for knob in Knob::VARIANTS
    {
        if knobs.contains(knob)
        {
            stage_knob(ctx, *knob)?;
        }
        else
        {
            remove_knob(ctx, *knob)?;
        }
    }
    Ok(())
}

/// The path in the sysroot's ESP of `path`, a path from the ESP's root.
fn staged(ctx: &BuildContext, path: &str) -> PathBuf
{
    ctx.sysroot_esp().join(path.trim_start_matches('/'))
}

/// The ESP copies of the installed bootloader: the one `\EFI\seraph\boot.efi`
/// names and the removable-media default the firmware boots.
pub fn bootloader_copies(ctx: &BuildContext, arch: Arch) -> [PathBuf; 2]
{
    bootloader_paths(arch).map(|path| staged(ctx, &path))
}

/// The ESP copy of the installed kernel, `\EFI\seraph\kernel`.
pub fn kernel_copy(ctx: &BuildContext) -> PathBuf
{
    staged(ctx, &kernel_path())
}

/// Compose the ESP of a pack of `arch` whose bundle is `harness`'s: copy the
/// installed bootloader to [`bootloader_copies`] and the installed kernel,
/// checked to verify as the bootloader will verify it, to [`kernel_copy`],
/// then compose the bundle ([`bundle::compose`]); then read the ESP back and
/// check it ([`check_staged`]). The sysroot must be signed for `harness`
/// already.
///
/// # Errors
///
/// When the installed kernel or bootloader is missing or unreadable, when the
/// kernel does not verify under the installed bootloader's trust store, those
/// of [`bundle::compose`] and [`check_staged`], and on an I/O failure
/// writing a copy.
pub fn compose(ctx: &BuildContext, arch: Arch, harness: Harness) -> Result<()>
{
    let store = installed_store(ctx)?;
    let kernel = read_installed(&ctx.installed_kernel())?;
    check_kernel(&store, arch, &kernel)?;
    let bootloader = read_installed(&ctx.installed_bootloader())?;
    for copy in bootloader_copies(ctx, arch)
    {
        write_copy(&copy, &bootloader)?;
    }
    write_copy(&kernel_copy(ctx), &kernel)?;
    bundle::compose(ctx, arch, harness, &bundle::esp_path(ctx))?;
    check_staged(ctx, arch, harness)?;
    crate::util::step(&format!(
        "ESP: {} (bootloader, kernel and bundle copied from installed files)",
        ctx.sysroot_esp().display()
    ));
    Ok(())
}

/// Check the ESP the sysroot stages (`sysroot/esp/`), read back whole, against
/// the sysroot's installed files and `harness`'s bundle list ([`check`]).
///
/// # Errors
///
/// Those of [`check`], and when the ESP, an installed file or the list cannot
/// be read.
fn check_staged(ctx: &BuildContext, arch: Arch, harness: Harness) -> Result<()>
{
    let root = ctx.sysroot_esp();
    let mut esp = BTreeMap::new();
    read_tree(&root, "", &mut esp)?;
    let lists = [bundle::read_list(ctx, arch, harness)?];
    let installed = |install: &str| -> Result<Option<Vec<u8>>> {
        let path = ctx.sysroot.join(install.trim_start_matches('/'));
        if path.is_file()
        {
            Ok(Some(
                fs::read(&path).with_context(|| format!("reading {}", path.display()))?,
            ))
        }
        else
        {
            Ok(None)
        }
    };
    check(&esp, &installed, arch, &lists).with_context(|| {
        format!(
            "the ESP composed at {} is not copies of the installed files",
            root.display()
        )
    })
}

/// Put every file under the directory `dir`, at `path` from the ESP's root,
/// into `out` by its path from the ESP's root, with its bytes. An entry other
/// than a file or a directory is skipped, as a pack skips it.
fn read_tree(dir: &Path, path: &str, out: &mut BTreeMap<String, Vec<u8>>) -> Result<()>
{
    let entries = fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    for entry in entries
    {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        let host = entry.path();
        let Ok(name) = entry.file_name().into_string()
        else
        {
            bail!("{} has a name that is not UTF-8", host.display());
        };
        let full = format!("{path}/{name}");
        let kind = entry
            .file_type()
            .with_context(|| format!("reading the type of {}", host.display()))?;
        if kind.is_dir()
        {
            read_tree(&host, &full, out)?;
        }
        else if kind.is_file()
        {
            let bytes = fs::read(&host).with_context(|| format!("reading {}", host.display()))?;
            out.insert(full, bytes);
        }
    }
    Ok(())
}

/// Check that every file of the ESP `esp`, by its path from the ESP's root,
/// is an object equal to the installed file it copies, the installed files
/// being those `installed` returns by install path (`None` for one that is
/// not installed) (docs/boot-media.md § The ESP):
///
/// - the bootloader's two copies ([`bootloader_copies`]) equal
///   `/boot/boot.efi`, and the kernel's copy ([`kernel_copy`]) `/boot/kernel`;
/// - the bundle ([`bundle::ESP_PATH`]) parses, its first entry is `init`, its
///   other entries are the entries of its bundle list, once each in the list's
///   order, and each entry equals the installed file the list names for it.
///   The list is the one of `lists` whose entries the bundle's are, or the one
///   list `lists` holds;
/// - `\EFI\seraph\trust-request`, when present, is a trust request
///   (`crate::signing::request::is_request`);
/// - every other file is empty and in `\EFI\seraph\`: a presence-only knob of
///   the bootloader, which carries no content and so is no object.
///
/// # Errors
///
/// Naming every object that is missing, differs from its installed file, or
/// copies an installed file that is missing; a bundle entry its list does not
/// name, or one the list names that the bundle lacks; and every other file
/// that is not a knob. Also those of `installed`.
pub fn check(
    esp: &BTreeMap<String, Vec<u8>>,
    installed: &dyn Fn(&str) -> Result<Option<Vec<u8>>>,
    arch: Arch,
    lists: &[BundleList],
) -> Result<()>
{
    let mut faults = Vec::new();
    let mut objects = Vec::new();
    let copies = bootloader_paths(arch)
        .into_iter()
        .map(|path| (path, BOOTLOADER_INSTALL))
        .chain([(kernel_path(), KERNEL_INSTALL)]);
    for (path, install) in copies
    {
        compare(
            &mut faults,
            &path,
            esp.get(&path).map(Vec::as_slice),
            install,
            installed,
        )?;
        objects.push(path);
    }
    match esp.get(bundle::ESP_PATH)
    {
        Some(bytes) => check_bundle(&mut faults, bytes, installed, lists)?,
        None => faults.push(format!("{} is missing", bundle::ESP_PATH)),
    }
    objects.push(bundle::ESP_PATH.to_owned());
    for (path, bytes) in esp
    {
        let knob = bytes.is_empty()
            && path
                .strip_prefix(VENDOR_DIR)
                .and_then(|rest| rest.strip_prefix('/'))
                .is_some_and(|name| !name.contains('/'));
        let request = *path == format!("{VENDOR_DIR}/{}", crate::signing::request::FILE_NAME)
            && crate::signing::request::is_request(bytes);
        if !knob && !request && !objects.contains(path)
        {
            faults.push(format!(
                "{path} is no object the ESP copies from an installed file, nor a knob, nor a \
                 trust request"
            ));
        }
    }
    if faults.is_empty()
    {
        return Ok(());
    }
    bail!("{}", faults.join("; "))
}

/// Add to `faults` that `held`, the object at `path` on the ESP, is missing,
/// or copies the installed file `install` that is missing, or differs from it.
fn compare(
    faults: &mut Vec<String>,
    path: &str,
    held: Option<&[u8]>,
    install: &str,
    installed: &dyn Fn(&str) -> Result<Option<Vec<u8>>>,
) -> Result<()>
{
    let Some(held) = held
    else
    {
        faults.push(format!("{path} is missing"));
        return Ok(());
    };
    match installed(install)?
    {
        None => faults.push(format!("{path} copies {install}, which is not installed")),
        Some(bytes) if bytes != held =>
        {
            faults.push(format!("{path} differs from its installed file {install}"));
        }
        Some(_) =>
        {}
    }
    Ok(())
}

/// Add to `faults` each way the bundle `bytes` is not the copies of the
/// installed files its bundle list, the one of `lists` [`check`] chooses,
/// names.
fn check_bundle(
    faults: &mut Vec<String>,
    bytes: &[u8],
    installed: &dyn Fn(&str) -> Result<Option<Vec<u8>>>,
    lists: &[BundleList],
) -> Result<()>
{
    let at = bundle::ESP_PATH;
    let entries = match bundle::parse_entries(bytes)
    {
        Ok(entries) => entries,
        Err(error) =>
        {
            faults.push(format!("{at}: {error:#}"));
            return Ok(());
        }
    };
    let Some(((first, _), modules)) = entries.split_first()
    else
    {
        faults.push(format!("{at} has no entry"));
        return Ok(());
    };
    if first != INIT_SLOT
    {
        faults.push(format!("{at}: its first entry is {first}, not {INIT_SLOT}"));
        return Ok(());
    }
    let names: Vec<&str> = modules.iter().map(|(name, _)| name.as_str()).collect();
    let list = if let [one] = lists
    {
        one
    }
    else
    {
        let Some(list) = lists.iter().find(|list| list.entries == names)
        else
        {
            faults.push(format!(
                "{at}: its entries are those of no harness's bundle list"
            ));
            return Ok(());
        };
        list
    };
    let before = faults.len();
    for name in &names
    {
        if !list.entries.iter().any(|entry| entry == name)
        {
            faults.push(format!(
                "{at}: its entry {name} is no object its list names"
            ));
        }
    }
    for entry in &list.entries
    {
        if !names.contains(&entry.as_str())
        {
            faults.push(format!("{at}: it lacks the entry {entry} its list names"));
        }
    }
    if faults.len() == before && list.entries != names
    {
        faults.push(format!(
            "{at}: its entries are not its list's, once each in its order"
        ));
    }
    for (name, body) in &entries
    {
        let install = if name == INIT_SLOT { &list.init } else { name };
        if name == INIT_SLOT || list.entries.contains(name)
        {
            compare(
                faults,
                &format!("{at} entry {name}"),
                Some(body),
                install,
                installed,
            )?;
        }
    }
    Ok(())
}

/// The bytes of the installed file at `path`.
fn read_installed(path: &std::path::Path) -> Result<Vec<u8>>
{
    fs::read(path).with_context(|| {
        format!(
            "reading the installed {} (run `cargo xtask build` first)",
            path.display()
        )
    })
}

/// Write `bytes` to `path`, creating its directory.
fn write_copy(path: &std::path::Path, bytes: &[u8]) -> Result<()>
{
    if let Some(parent) = path.parent()
    {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
}

/// Check `kernel` as the bootloader will: an object that verifies under the
/// encoded trust store `store` with the kernel role, under the name
/// `kernel`, for `arch`.
fn check_kernel(store: &[u8], arch: Arch, kernel: &[u8]) -> Result<()>
{
    let store = TrustStore::parse(store)
        .map_err(|e| err!("the installed trust store does not parse ({e:?})"))?;
    let expect = Expectation {
        roles: RoleSet::of(&[Role::Kernel]),
        name: KERNEL_NAME.as_bytes(),
        arch: objsig_arch(arch),
    };
    objsig::verify(kernel, &store, &expect)
        .map(|_| ())
        .map_err(|refusal| {
            err!(
                "the installed kernel does not verify as the bootloader will verify it \
                 ({refusal:?}): sign the sysroot first (`cargo xtask mkdisk`)"
            )
        })
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::signing::sign_sysroot;
    use crate::signing::testing::{install_lists, scratch, signer};
    use boot_protocol::bundle as fmt;

    /// An ESP of the installed files `installed` for x86_64 whose bundle is the
    /// one of `list`, holding the `nokaslr` knob.
    fn esp_of(installed: &BTreeMap<String, Vec<u8>>, list: &BundleList)
    -> BTreeMap<String, Vec<u8>>
    {
        let dir = scratch("esp-of");
        let out = dir.join("bundle");
        let entries: Vec<(String, Vec<u8>)> = std::iter::once((INIT_SLOT.to_owned(), &list.init))
            .chain(list.entries.iter().map(|path| (path.clone(), path)))
            .map(|(name, install)| (name, installed[install].clone()))
            .collect();
        bundle::write_bundle(&out, u32::try_from(entries.len()).unwrap(), &entries).unwrap();
        let mut esp = BTreeMap::new();
        for path in bootloader_paths(Arch::X86_64)
        {
            esp.insert(path, installed[BOOTLOADER_INSTALL].clone());
        }
        esp.insert(kernel_path(), installed[KERNEL_INSTALL].clone());
        esp.insert(bundle::ESP_PATH.to_owned(), fs::read(&out).unwrap());
        esp.insert(format!("{VENDOR_DIR}/nokaslr"), Vec::new());
        let _ = fs::remove_dir_all(&dir);
        esp
    }

    /// Installed files, and the bundle lists of two harnesses over them.
    fn installed_files() -> (BTreeMap<String, Vec<u8>>, [BundleList; 2])
    {
        let mut installed = BTreeMap::new();
        for path in [
            BOOTLOADER_INSTALL,
            KERNEL_INSTALL,
            "/services/init",
            "/services/vfsd",
            "/config/table",
            "/tests/ktest",
        ]
        {
            installed.insert(path.to_owned(), format!("the bytes of {path}").into_bytes());
        }
        let lists = [
            BundleList {
                init: "/tests/ktest".to_owned(),
                entries: Vec::new(),
            },
            BundleList {
                init: "/services/init".to_owned(),
                entries: vec!["/services/vfsd".to_owned(), "/config/table".to_owned()],
            },
        ];
        (installed, lists)
    }

    /// The check of `esp` against `installed` and `lists`, and its message when it fails.
    fn checked(
        esp: &BTreeMap<String, Vec<u8>>,
        installed: &BTreeMap<String, Vec<u8>>,
        lists: &[BundleList],
    ) -> std::result::Result<(), String>
    {
        let lookup = |path: &str| -> Result<Option<Vec<u8>>> { Ok(installed.get(path).cloned()) };
        check(esp, &lookup, Arch::X86_64, lists).map_err(|error| format!("{error:#}"))
    }

    // Defect caught: a check that refuses the ESP every pack composes (a knob taken for a stray
    // object, the bundle's harness not found among the lists), so no image could be packed.
    #[test]
    fn an_esp_of_its_installed_files_passes_the_check()
    {
        let (installed, lists) = installed_files();
        for list in &lists
        {
            let esp = esp_of(&installed, list);
            checked(&esp, &installed, &lists).unwrap();
            checked(&esp, &installed, std::slice::from_ref(list)).unwrap();
        }
    }

    // Defect caught: an ESP object that differs from its installed file (a stale copy, a
    // repack that changed one side alone, either bootloader copy, the kernel, a bundle entry)
    // accepted, or refused without naming the object.
    #[test]
    fn an_object_that_differs_from_its_installed_file_is_refused_naming_it()
    {
        let (installed, lists) = installed_files();
        let good = esp_of(&installed, &lists[1]);
        let [named, fallback] = bootloader_paths(Arch::X86_64);
        for path in [named, fallback, kernel_path()]
        {
            let mut esp = good.clone();
            esp.get_mut(&path).unwrap().push(0);
            let error = checked(&esp, &installed, &lists).unwrap_err();
            assert!(error.contains(&format!("{path} differs")), "{error}");
        }
        for (install, entry) in [
            ("/services/init", "init"),
            ("/config/table", "/config/table"),
        ]
        {
            let mut changed = installed.clone();
            changed.get_mut(install).unwrap().push(0);
            let error = checked(&good, &changed, &lists).unwrap_err();
            assert!(
                error.contains(&format!(
                    "entry {entry} differs from its installed file {install}"
                )),
                "{error}"
            );
        }
    }

    // Defect caught: an object whose installed file is gone, or an object missing from the
    // ESP, taken as equal.
    #[test]
    fn an_object_or_installed_file_that_is_missing_is_refused_naming_it()
    {
        let (installed, lists) = installed_files();
        let good = esp_of(&installed, &lists[1]);
        for install in [KERNEL_INSTALL, "/services/vfsd"]
        {
            let mut gone = installed.clone();
            gone.remove(install);
            let error = checked(&good, &gone, &lists).unwrap_err();
            assert!(
                error.contains(&format!("copies {install}, which is not installed")),
                "{error}"
            );
        }
        for path in [kernel_path(), bundle::ESP_PATH.to_owned()]
        {
            let mut esp = good.clone();
            esp.remove(&path);
            let error = checked(&esp, &installed, &lists).unwrap_err();
            assert!(error.contains(&format!("{path} is missing")), "{error}");
        }
    }

    // Defect caught: a bundle whose entries are not its list's (an extra entry, one the list
    // names missing, the entries out of order, a module in the init slot, a bundle that does
    // not parse) accepted.
    #[test]
    fn a_bundle_whose_entries_are_not_its_lists_is_refused()
    {
        let (installed, lists) = installed_files();
        let list = &lists[1];
        let refused = |entries: Vec<&str>, first: Option<&str>, says: &str| {
            let changed = BundleList {
                init: list.init.clone(),
                entries: entries.iter().map(|path| (*path).to_owned()).collect(),
            };
            let mut esp = esp_of(&installed, &changed);
            if let Some(name) = first
            {
                // Another name in the init slot.
                let bytes = esp.get_mut(bundle::ESP_PATH).unwrap();
                let at = fmt::HEADER_SIZE;
                bytes[at..at + fmt::ENTRY_NAME_LEN].fill(0);
                bytes[at..at + name.len()].copy_from_slice(name.as_bytes());
            }
            let error = checked(&esp, &installed, std::slice::from_ref(list)).unwrap_err();
            assert!(error.contains(says), "{error}");
        };
        refused(
            vec!["/services/vfsd", "/config/table", "/tests/ktest"],
            None,
            "entry /tests/ktest is no object its list names",
        );
        refused(
            vec!["/services/vfsd"],
            None,
            "lacks the entry /config/table",
        );
        refused(
            vec!["/config/table", "/services/vfsd"],
            None,
            "not its list's, once each in its order",
        );
        refused(
            vec!["/services/vfsd", "/config/table"],
            Some("/services/init"),
            "its first entry is /services/init",
        );
        // Among several lists, one whose entries the bundle's are none of.
        let esp = esp_of(
            &installed,
            &BundleList {
                init: list.init.clone(),
                entries: vec!["/services/vfsd".to_owned()],
            },
        );
        let error = checked(&esp, &installed, &lists).unwrap_err();
        assert!(error.contains("no harness's bundle list"), "{error}");
        let mut esp = esp_of(&installed, list);
        esp.get_mut(bundle::ESP_PATH).unwrap().truncate(8);
        let error = checked(&esp, &installed, &lists).unwrap_err();
        assert!(error.contains("does not parse"), "{error}");
    }

    // Defect caught: a hand-placed or stale file on the ESP, which the firmware or the
    // bootloader could load and no installed file stands behind, accepted beside the objects.
    #[test]
    fn a_file_that_is_neither_an_object_nor_a_knob_is_refused()
    {
        let (installed, lists) = installed_files();
        let good = esp_of(&installed, &lists[1]);
        for (path, bytes) in [
            ("/EFI/seraph/init", b"\x7fELF".as_slice()),
            ("/EFI/seraph/nokaslr", b"x"),
            ("/EFI/BOOT/knob", b""),
            ("/EFI/seraph/sub/knob", b""),
        ]
        {
            let mut esp = good.clone();
            esp.insert(path.to_owned(), bytes.to_vec());
            let error = checked(&esp, &installed, &lists).unwrap_err();
            assert!(error.contains(&format!("{path} is no object")), "{error}");
        }
    }

    // Defect caught: a trust request staged for the bootloader refused, so no
    // image could carry one, or any file accepted under its name, or a request
    // accepted at another path, where no bootloader reads it.
    #[test]
    fn a_trust_request_is_accepted_at_its_path_alone()
    {
        let (installed, lists) = installed_files();
        let good = esp_of(&installed, &lists[1]);
        let revoke = [[1u8; objsig::KEY_ID_LEN]];
        let mut request = vec![0u8; objsig::enrol::encoded_len(0, revoke.len()).unwrap()];
        objsig::enrol::TrustRequest::encode(&[], &revoke, &mut request).unwrap();
        let path = format!("{VENDOR_DIR}/{}", crate::signing::request::FILE_NAME);

        let mut esp = good.clone();
        esp.insert(path.clone(), request.clone());
        checked(&esp, &installed, &lists).unwrap();

        for (at, bytes) in [
            (path.as_str(), b"not a request".as_slice()),
            ("/EFI/seraph/trust-request.old", request.as_slice()),
        ]
        {
            let mut esp = good.clone();
            esp.insert(at.to_owned(), bytes.to_vec());
            let error = checked(&esp, &installed, &lists).unwrap_err();
            assert!(error.contains(&format!("{at} is no object")), "{error}");
        }
    }

    // Defect caught: an ESP object that is not its installed file byte for
    // byte (a composer that signs or re-signs, a stale copy left from an
    // earlier pack, a fallback bootloader that differs from the named one),
    // an installed file the composer changes, an unsigned kernel copied to
    // an ESP the bootloader would refuse, or a composition that leaves a file
    // it does not copy on the ESP unchecked.
    #[test]
    fn the_esp_is_byte_copies_of_the_installed_files()
    {
        let arch = Arch::X86_64;
        let root = scratch("esp");
        let ctx = BuildContext {
            root: root.clone(),
            sysroot: root.join("sysroot"),
            target_dir: root.join("target"),
        };
        let signer = signer(&root.join("keys"), arch);
        install_lists(&ctx);
        for harness in Harness::VARIANTS
        {
            let list = bundle::read_list(&ctx, arch, *harness).unwrap();
            for install in std::iter::once(&list.init).chain(&list.entries)
            {
                let path = ctx.sysroot.join(&install[1..]);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(&path, format!("\x7fELF {install}")).unwrap();
            }
        }
        crate::signing::testing::install_policy(&ctx);
        let mut image = b"MZ bootloader".to_vec();
        image.extend_from_slice(&objsig::embed::MARKER);
        image.extend_from_slice(&u32::try_from(signer.store().len()).unwrap().to_le_bytes());
        image.extend_from_slice(signer.store());
        fs::create_dir_all(ctx.sysroot_boot()).unwrap();
        fs::write(ctx.installed_bootloader(), &image).unwrap();
        fs::write(ctx.installed_kernel(), b"\x7fELF kernel").unwrap();
        // A stale copy of an earlier pack.
        fs::create_dir_all(ctx.sysroot_efi_seraph()).unwrap();
        fs::write(kernel_copy(&ctx), b"stale kernel").unwrap();

        compose(&ctx, arch, Harness::Init).unwrap_err();
        sign_sysroot(&ctx, &signer, arch, Harness::Init).unwrap();
        let kernel = fs::read(ctx.installed_kernel()).unwrap();
        compose(&ctx, arch, Harness::Init).unwrap();
        assert_eq!(fs::read(ctx.installed_kernel()).unwrap(), kernel);
        assert_eq!(fs::read(kernel_copy(&ctx)).unwrap(), kernel);
        assert_eq!(fs::read(ctx.installed_bootloader()).unwrap(), image);
        for copy in bootloader_copies(&ctx, arch)
        {
            assert_eq!(fs::read(&copy).unwrap(), image, "{}", copy.display());
        }
        assert!(bundle::esp_path(&ctx).is_file());

        // A file the composer does not copy, left on the ESP, is refused.
        let stray = ctx.sysroot_efi_seraph().join("stray.efi");
        fs::write(&stray, b"MZ stray").unwrap();
        let error = format!("{:#}", compose(&ctx, arch, Harness::Init).unwrap_err());
        assert!(
            error.contains("/EFI/seraph/stray.efi is no object"),
            "{error}"
        );
        fs::remove_file(&stray).unwrap();
        compose(&ctx, arch, Harness::Init).unwrap();

        // A kernel signed under another name is refused.
        signer
            .sign_file(
                &ctx.installed_kernel(),
                RoleSet::of(&[Role::Kernel]),
                "/boot/kernel",
            )
            .unwrap();
        compose(&ctx, arch, Harness::Init).unwrap_err();
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: a knob an earlier pack staged surviving a pack that did not name it (KASLR
    // left off, or the map redo left on, for every later boot), or a named knob not staged.
    #[test]
    fn the_knobs_staged_are_exactly_the_ones_named()
    {
        let dir = scratch("knobs");
        let ctx = BuildContext {
            root: dir.clone(),
            sysroot: dir.join("sysroot"),
            target_dir: dir.join("target"),
        };
        let staged = |ctx: &BuildContext| -> Vec<Knob> {
            Knob::VARIANTS
                .iter()
                .copied()
                .filter(|knob| knob_path(ctx, *knob).is_file())
                .collect()
        };
        set_knobs(&ctx, &[Knob::NoKaslr, Knob::MapRedo]).unwrap();
        assert_eq!(staged(&ctx), [Knob::NoKaslr, Knob::MapRedo]);
        set_knobs(&ctx, &[Knob::MapRedo]).unwrap();
        assert_eq!(staged(&ctx), [Knob::MapRedo]);
        set_knobs(&ctx, &[]).unwrap();
        assert_eq!(staged(&ctx), []);
        let _ = fs::remove_dir_all(&dir);
    }
}
