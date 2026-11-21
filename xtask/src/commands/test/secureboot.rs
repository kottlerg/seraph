// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test/secureboot.rs

//! Secure Boot test: the firmware boots the bootloader signed with an
//! enrolled key and refuses it tampered or unsigned, and the bootloader logs
//! the Secure Boot state (docs/signing.md § Secure Boot).
//!
//! The case generates a development PK, KEK and db ([`DevKeys`]) and signs
//! the installed bootloader with the db key, then boots four times, each on
//! a variable store of its own, with the image in place of both ESP copies of
//! the installed one:
//!
//! - `enrolled`: the signed bootloader, on the Secure Boot firmware
//!   ([`Firmware::prepare_secure_boot`]) with the three keys enrolled; owes
//!   the bootloader's `Secure Boot: on` line.
//! - `tampered`: the signed bootloader with a byte of its code flipped, on
//!   the same firmware and keys; owes the firmware's refusal.
//! - `unsigned`: the bootloader with no signature; owes the refusal.
//! - `default`: the installed bootloader on the default firmware and its
//!   template store; owes the bootloader's `Secure Boot: off` line.
//!
//! A boot passes when every line it is owed appears, as the `signing` case
//! judges one. A firmware that does not enforce Secure Boot fails the first
//! three boots, and the failure names it: the case never passes on a
//! firmware that boots what it should refuse. Every boot's serial log, the
//! keys and the images are saved under `target/xtask/test/secureboot/<arch>/`.
//! The disk images are packed again in the layout they had, with the
//! recorded harness's bundle.
//!
//! Requires a populated sysroot from `cargo xtask build` whose recorded
//! harness is `init`, as the case registry checks, and sbsigntools, openssl
//! and virt-firmware's `virt-fw-vars` on the host.

use std::fs;
use std::path::Path;
use std::process::Command;

use crate::arch::Arch;
use crate::commands::test::cases::CaseArgs;
use crate::commands::test::signing::{BOOTLOADER_TIMEOUT, Case, boot_case, read_sysroot, stage};
use crate::context::Context;
use crate::disk::Substitute;
use crate::error::{Context as _, Result, bail, ensure};
use crate::firmware;
use crate::qemu::{Firmware, validate_sysroot_for_launch};
use crate::secure_boot::{DevKeys, enroll, sign};
use crate::util::{require_tool, step};

/// The sysroot path of the installed bootloader.
const BOOTLOADER: &str = "boot/boot.efi";

/// The bootloader's line once the firmware verified it
/// (`core/boot/src/secure_boot.rs`).
const STATE_ON: &str = "boot: Secure Boot: on";

/// The start of the bootloader's line when Secure Boot is off, whatever the
/// reason it gives.
const STATE_OFF: &str = "boot: Secure Boot: off";

/// EDK2's boot manager's line once Secure Boot refused an image (`BdsDxe`).
const FIRMWARE_REFUSAL: &str = "Access Denied -- rejected probably by Secure Boot";

/// A boot on the Secure Boot firmware, or on the default one.
#[derive(Clone, Copy, PartialEq, Eq)]
enum On
{
    SecureBoot,
    Default,
}

pub fn run(ctx: &Context, args: &CaseArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, args.arch)?;
    let dir = ctx
        .target_dir
        .join("xtask")
        .join("test")
        .join("secureboot")
        .join(args.arch.to_string());
    match fs::remove_dir_all(&dir)
    {
        Ok(()) =>
        {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound =>
        {}
        Err(e) => return Err(e).with_context(|| format!("removing {}", dir.display())),
    }
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    // Read before anything changes, so a failure cannot change what the
    // restore writes.
    let layout = crate::disk::current_layout(ctx)?;
    let results = prepare(ctx, args.arch, &dir).and_then(|(keys, cases)| {
        // Resolved before the boots, so a host without a Secure Boot
        // firmware fails here, naming what it looked for.
        let secure = Firmware::prepare_secure_boot(ctx, args.arch)?;
        let default = Firmware::prepare(ctx, args.arch)?;
        // Held until the last boot's QEMU has exited.
        let _host = crate::host_lock::admit_boot(ctx, &args.host, args.cpus, 1)?;
        Ok(cases
            .iter()
            .map(|(on, case)| {
                step(&format!("secure boot test: {}: booting", case.name));
                let booted = match on
                {
                    On::SecureBoot => secure.launch_vars().and_then(|vars| {
                        enroll(vars.path(), &keys.pk.cert, &keys.kek.cert, &keys.db.cert)?;
                        boot_case(ctx, args, layout, &dir, case, &secure, vars.path())
                    }),
                    On::Default => default.launch_vars().and_then(|vars| {
                        boot_case(ctx, args, layout, &dir, case, &default, vars.path())
                    }),
                };
                let booted = booted.with_context(|| match on
                {
                    On::SecureBoot => not_enforcing(args.arch, &secure),
                    On::Default => format!("the default firmware {}", default.code.display()),
                });
                (case.name, booted)
            })
            .collect::<Vec<_>>())
    });
    // Restore first, and surface its failure ahead of the boots': images
    // carrying a refused bootloader would fail every later boot.
    crate::disk::create_disk_image(ctx, args.arch, layout)
        .context("packing the disk images again from the sysroot")?;
    let mut failed = Vec::new();
    for (name, result) in results?
    {
        match result
        {
            Ok(()) => step(&format!("secure boot test: {name}: PASS")),
            Err(e) =>
            {
                step(&format!("secure boot test: {name}: FAIL: {e:#}"));
                failed.push(name);
            }
        }
    }
    if !failed.is_empty()
    {
        bail!(
            "secure boot test: {} failed (logs under {})",
            failed.join(", "),
            dir.display()
        );
    }
    step(
        "secure boot test: PASS (the firmware booted the signed bootloader and refused the others)",
    );
    Ok(())
}

/// What a failed boot on `firmware`, `arch`'s Secure Boot firmware, may
/// mean: a firmware built without Secure Boot boots every image, so the
/// refusals never come and the bootloader reports Secure Boot off.
fn not_enforcing(arch: Arch, firmware: &Firmware) -> String
{
    let (code, vars) = match arch
    {
        Arch::X86_64 => (
            firmware::ENV_OVMF_SECURE_CODE,
            firmware::ENV_OVMF_SECURE_VARS,
        ),
        Arch::Riscv64 => (
            firmware::ENV_RISCV_SECURE_CODE,
            firmware::ENV_RISCV_SECURE_VARS,
        ),
    };
    format!(
        "on the Secure Boot firmware {}: a firmware built without Secure Boot boots every image; \
         docs/build-system.md § QEMU and Firmware names the builds that enforce it, and {code} \
         with {vars} selects one",
        firmware.code.display()
    )
}

/// The keys, and the four boots with their images under `dir`.
fn prepare(ctx: &Context, arch: Arch, dir: &Path) -> Result<(DevKeys, Vec<(On, Case)>)>
{
    step("secure boot test: generating a development PK, KEK and db");
    let keys = DevKeys::generate(&dir.join("keys"))?;
    let installed = read_sysroot(ctx, BOOTLOADER)?;
    let unsigned = stage(dir, "boot.efi.unsigned", &strip_signatures(&installed)?)?;
    let signed = dir.join("boot.efi.signed");
    sign(&unsigned, &signed, &keys.db)?;
    let tampered_bytes = flip_code_byte(&fs::read(&signed).context("reading the signed image")?)?;
    let tampered = stage(dir, "boot.efi.tampered", &tampered_bytes)?;
    refuse_check(&tampered, &keys.db.cert)?;

    let copies = |image: &Path| bootloader_substitutes(ctx, arch, image);
    let refused = |name: &'static str, image: &Path| -> Result<(On, Case)> {
        Ok((
            On::SecureBoot,
            Case {
                name,
                substitutes: copies(image)?,
                expect: vec![FIRMWARE_REFUSAL.to_owned()],
                timeout: BOOTLOADER_TIMEOUT,
            },
        ))
    };
    Ok((
        keys,
        vec![
            (
                On::SecureBoot,
                Case {
                    name: "enrolled",
                    substitutes: copies(&signed)?,
                    expect: vec![STATE_ON.to_owned()],
                    timeout: BOOTLOADER_TIMEOUT,
                },
            ),
            refused("tampered", &tampered)?,
            refused("unsigned", &unsigned)?,
            (
                On::Default,
                Case {
                    name: "default",
                    substitutes: Vec::new(),
                    expect: vec![STATE_OFF.to_owned()],
                    timeout: BOOTLOADER_TIMEOUT,
                },
            ),
        ],
    ))
}

/// Check that `sbverify` refuses `image` under `cert`, so a boot of it
/// tests the firmware, not a tamper that missed the signed bytes.
fn refuse_check(image: &Path, cert: &Path) -> Result<()>
{
    let sbverify = require_tool("sbverify")?;
    let status = Command::new(&sbverify)
        .arg("--cert")
        .arg(cert)
        .arg(image)
        .output()
        .with_context(|| format!("failed to launch {}", sbverify.display()))?
        .status;
    ensure!(
        !status.success(),
        "sbverify accepts the tampered image {}: the flipped byte is outside the signed bytes",
        image.display()
    );
    Ok(())
}

/// `image` as the substitute of both ESP copies of the installed bootloader.
fn bootloader_substitutes(ctx: &Context, arch: Arch, image: &Path) -> Result<Vec<Substitute>>
{
    crate::esp::bootloader_copies(ctx, arch)
        .into_iter()
        .map(|copy| {
            let relative = copy
                .strip_prefix(&ctx.sysroot)
                .with_context(|| format!("{} is outside the sysroot", copy.display()))?;
            Ok(Substitute {
                path: relative.to_path_buf(),
                source: image.to_path_buf(),
            })
        })
        .collect()
}

/// The fields of a PE32+ image the case reads.
#[derive(Debug, PartialEq, Eq)]
struct PeLayout
{
    /// The file offset of the certificate table's data-directory entry.
    security_entry: usize,
    /// The certificate table: its file offset and size; size 0 for none.
    security: (usize, usize),
    /// The first code section's raw data: its file offset and size.
    code: (usize, usize),
}

/// The PE32+ magic of the optional header.
const PE32_PLUS: u16 = 0x20b;

/// The section characteristic of code.
const SCN_CNT_CODE: u32 = 0x20;

/// The index of the certificate table among the data directories.
const SECURITY_DIRECTORY: usize = 4;

fn read_u16(image: &[u8], at: usize) -> Result<u16>
{
    let bytes = image
        .get(at..at.saturating_add(2))
        .with_context(|| format!("a PE field at {at:#x} past the image's end"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(image: &[u8], at: usize) -> Result<usize>
{
    let bytes = image
        .get(at..at.saturating_add(4))
        .with_context(|| format!("a PE field at {at:#x} past the image's end"))?;
    usize::try_from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .context("a PE field past usize")
}

/// Read `image`'s [`PeLayout`].
///
/// # Errors
///
/// When `image` is not a PE32+ image with a certificate-table entry and a
/// code section with raw data.
fn pe_layout(image: &[u8]) -> Result<PeLayout>
{
    ensure!(image.starts_with(b"MZ"), "not a PE image: no MZ header");
    let pe = read_u32(image, 0x3c)?;
    ensure!(
        image.get(pe..pe.saturating_add(4)) == Some(b"PE\0\0".as_slice()),
        "not a PE image: no PE signature at {pe:#x}"
    );
    let sections = usize::from(read_u16(image, pe + 6)?);
    let optional_size = usize::from(read_u16(image, pe + 20)?);
    let optional = pe + 24;
    ensure!(read_u16(image, optional)? == PE32_PLUS, "not a PE32+ image");
    ensure!(
        read_u32(image, optional + 108)? > SECURITY_DIRECTORY,
        "the image has no certificate-table entry"
    );
    let security_entry = optional + 112 + SECURITY_DIRECTORY * 8;
    let security = (
        read_u32(image, security_entry)?,
        read_u32(image, security_entry + 4)?,
    );
    let table = optional + optional_size;
    let code = (0..sections)
        .map(|index| table + index * 40)
        .find_map(|header| {
            let characteristics = read_u32(image, header + 36).ok()?;
            let size = read_u32(image, header + 16).ok()?;
            let offset = read_u32(image, header + 20).ok()?;
            (characteristics & SCN_CNT_CODE as usize != 0 && size != 0).then_some((offset, size))
        })
        .context("the image has no code section with raw data")?;
    Ok(PeLayout {
        security_entry,
        security,
        code,
    })
}

/// `image` with every Authenticode signature removed: its certificate table,
/// which ends the file, cut off, and the table's entry cleared. An unsigned
/// image is returned as it is.
///
/// # Errors
///
/// Those of [`pe_layout`], and when the table does not end the file.
fn strip_signatures(image: &[u8]) -> Result<Vec<u8>>
{
    let layout = pe_layout(image)?;
    let (offset, size) = layout.security;
    if size == 0
    {
        return Ok(image.to_vec());
    }
    ensure!(
        offset.checked_add(size) == Some(image.len()),
        "the certificate table ({offset:#x}, {size:#x} bytes) does not end the {}-byte image",
        image.len()
    );
    let mut out = image[..offset].to_vec();
    out[layout.security_entry..layout.security_entry + 8].fill(0);
    Ok(out)
}

/// `image` with the middle byte of its first code section inverted, a byte
/// the Authenticode hash covers.
///
/// # Errors
///
/// Those of [`pe_layout`], and when that byte is past the image's end.
fn flip_code_byte(image: &[u8]) -> Result<Vec<u8>>
{
    let (offset, size) = pe_layout(image)?.code;
    let at = offset + size / 2;
    let mut out = image.to_vec();
    let byte = out
        .get_mut(at)
        .with_context(|| format!("the code section's byte {at:#x} is past the image's end"))?;
    *byte = !*byte;
    Ok(out)
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A minimal PE32+ image: the headers, one code section of 16 bytes at
    /// 0x200, and `table` as its certificate table after it.
    fn image(table: &[u8]) -> Vec<u8>
    {
        let mut out = vec![0u8; 0x200];
        out[..2].copy_from_slice(b"MZ");
        let pe = 0x80usize;
        out[0x3c..0x40].copy_from_slice(&u32::try_from(pe).unwrap().to_le_bytes());
        out[pe..pe + 4].copy_from_slice(b"PE\0\0");
        out[pe + 6..pe + 8].copy_from_slice(&1u16.to_le_bytes());
        let optional_size: u16 = 112 + 16 * 8;
        out[pe + 20..pe + 22].copy_from_slice(&optional_size.to_le_bytes());
        let optional = pe + 24;
        out[optional..optional + 2].copy_from_slice(&PE32_PLUS.to_le_bytes());
        out[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
        let section = optional + usize::from(optional_size);
        out[section + 16..section + 20].copy_from_slice(&16u32.to_le_bytes());
        out[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        out[section + 36..section + 40].copy_from_slice(&SCN_CNT_CODE.to_le_bytes());
        out.extend_from_slice(&[0x90; 16]);
        if !table.is_empty()
        {
            let entry = optional + 112 + SECURITY_DIRECTORY * 8;
            let at = u32::try_from(out.len()).unwrap();
            out[entry..entry + 4].copy_from_slice(&at.to_le_bytes());
            out[entry + 4..entry + 8]
                .copy_from_slice(&u32::try_from(table.len()).unwrap().to_le_bytes());
            out.extend_from_slice(table);
        }
        out
    }

    // Defect caught: an "unsigned" image that still carries a signature (the
    // build's, with SERAPH_SECURE_BOOT_KEY set), so the refusal it owes is
    // of a foreign key, or one cut so that it is no longer a PE image.
    #[test]
    fn stripping_leaves_the_unsigned_image()
    {
        let unsigned = image(&[]);
        assert_eq!(strip_signatures(&unsigned).unwrap(), unsigned);
        let signed = image(&[0xAB; 24]);
        assert_eq!(strip_signatures(&signed).unwrap(), unsigned);
        let mut trailing = signed.clone();
        trailing.push(0);
        strip_signatures(&trailing).unwrap_err();
    }

    // Defect caught: a tamper outside the hashed bytes (the certificate
    // table, the headers), so the "tampered" boot tests nothing.
    #[test]
    fn the_flipped_byte_is_in_the_code_section()
    {
        let signed = image(&[0xAB; 24]);
        let tampered = flip_code_byte(&signed).unwrap();
        let differing: Vec<usize> = (0..signed.len())
            .filter(|&i| signed[i] != tampered[i])
            .collect();
        assert_eq!(differing, [0x208]);
    }

    #[test]
    fn a_non_pe_image_is_refused()
    {
        pe_layout(b"ELF").unwrap_err();
        let mut pe32 = image(&[]);
        pe32[0x80 + 24] = 0x0b;
        pe32[0x80 + 25] = 0x01;
        pe_layout(&pe32).unwrap_err();
    }

    // Defect caught: an owed line that differs from the bootloader's, so the
    // enrolled or the default boot fails at its deadline.
    #[test]
    fn the_owed_state_lines_are_the_bootloaders()
    {
        let source = include_str!("../../../../core/boot/src/secure_boot.rs");
        assert!(source.contains(&format!("{STATE_ON} (")), "{STATE_ON}");
        assert!(source.contains(&format!("{STATE_OFF} (")), "{STATE_OFF}");
    }
}
