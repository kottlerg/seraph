// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/esp.rs

//! Compose the ESP the sysroot stages (`sysroot/esp/`) from installed files
//! (docs/boot-media.md § The ESP): the bootloader at `\EFI\seraph\boot.efi`
//! and at the firmware's removable-media default, the kernel at
//! `\EFI\seraph\kernel`, each a byte copy of its installed file under
//! `/boot/`, and the bundle ([`crate::bundle::compose`]). Every pack composes
//! it as its last step before it writes the images
//! (`crate::disk::create_disk_image`), so the ESP of every image equals the
//! installed files it derives from.
//!
//! Composing signs nothing and reads no key: the sysroot is signed first
//! (`crate::signing::sign_for_harness`), and the composer checks what it
//! copies as the bootloader will, under the trust store the installed
//! bootloader embeds.

use std::fs;
use std::path::PathBuf;

use objsig::{Expectation, Role, RoleSet, TrustStore};

use crate::arch::Arch;
use crate::bundle::{self, Harness};
use crate::context::Context as BuildContext;
use crate::error::{Context as _, Result, err};
use crate::signing::{installed_store, objsig_arch};

/// The name the kernel is signed under (docs/signing.md § Signing).
const KERNEL_NAME: &str = "kernel";

/// The ESP copies of the installed bootloader: the one `\EFI\seraph\boot.efi`
/// names and the removable-media default the firmware boots.
pub fn bootloader_copies(ctx: &BuildContext, arch: Arch) -> [PathBuf; 2]
{
    [
        ctx.sysroot_efi_seraph().join("boot.efi"),
        ctx.sysroot_efi_boot().join(arch.boot_efi_filename()),
    ]
}

/// The ESP copy of the installed kernel, `\EFI\seraph\kernel`.
pub fn kernel_copy(ctx: &BuildContext) -> PathBuf
{
    ctx.sysroot_efi_seraph().join(KERNEL_NAME)
}

/// Compose the ESP of a pack of `arch` whose bundle is `harness`'s: copy the
/// installed bootloader to [`bootloader_copies`] and the installed kernel,
/// checked to verify as the bootloader will verify it, to [`kernel_copy`],
/// then compose the bundle ([`bundle::compose`]). The sysroot must be signed
/// for `harness` already.
///
/// # Errors
///
/// When the installed kernel or bootloader is missing or unreadable, when the
/// kernel does not verify under the installed bootloader's trust store, those
/// of [`bundle::compose`], and on an I/O failure writing a copy.
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
    crate::util::step(&format!(
        "ESP: {} (bootloader, kernel and bundle copied from installed files)",
        ctx.sysroot_esp().display()
    ));
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
    use crate::argparse::ValueEnum as _;
    use crate::signing::sign_sysroot;
    use crate::signing::testing::{install_lists, scratch, signer};

    // Defect caught: an ESP object that is not its installed file byte for
    // byte (a composer that signs or re-signs, a stale copy left from an
    // earlier pack, a fallback bootloader that differs from the named one),
    // an installed file the composer changes, or an unsigned kernel copied to
    // an ESP the bootloader would refuse.
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

        // A kernel signed under another name is refused.
        signer
            .sign_file(&ctx.installed_kernel(), RoleSet::of(&[Role::Kernel]), "/boot/kernel")
            .unwrap();
        compose(&ctx, arch, Harness::Init).unwrap_err();
        let _ = fs::remove_dir_all(&root);
    }
}
