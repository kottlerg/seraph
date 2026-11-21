// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test/rollback.rs

//! Rollback floor test: the bootloader keeps the machine's security floor in
//! firmware storage, raises it, and refuses itself below it
//! (docs/signing.md § Rollback Floor).
//!
//! The case boots three times on one variable store, the firmware's
//! template copied once, so each boot sees the floor the one before it left:
//!
//! - `first`: the sysroot's images; the bootloader finds no floor and
//!   writes the floor `F` of its trust store.
//! - `raised`: a bootloader built under the build's store with the floor
//!   `F + 1`, in place of both ESP copies of the installed one, with the
//!   kernel and every bundle entry signed again at security version `F + 1`;
//!   it finds `F` and raises the floor to `F + 1`.
//! - `older`: the sysroot's images again; the bootloader finds `F + 1`
//!   above its store's `F` and refuses itself.
//!
//! A boot passes when every line it is owed appears, as the `signing`
//! case judges one; a boot after a failed one is not made, since it would
//! read a floor its predecessor did not leave. Every boot's serial log is
//! saved under `target/xtask/test/rollback/<arch>/`. The sysroot is left as
//! it was, apart from the signing every pack does, and the disk images are
//! packed again in the layout they had, with the recorded harness's bundle.
//!
//! Requires a populated sysroot from `cargo xtask build` whose recorded
//! harness is `init`, as the case registry checks.

use std::fs;
use std::path::Path;

use objsig::{RoleSet, TrustStore};

use crate::bundle::Harness;
use crate::commands::test::cases::CaseArgs;
use crate::commands::test::signing::{
    BOOT_FATAL, BOOTLOADER_TIMEOUT, BUNDLE, Case, ESP_KERNEL, KERNEL, boot_case, bootloader_under,
    read_sysroot, stage, sub,
};
use crate::context::Context;
use crate::error::{Context as _, Result, ensure, err};
use crate::qemu::{Firmware, validate_sysroot_for_launch};
use crate::signing::Signer;
use crate::util::step;

pub fn run(ctx: &Context, args: &CaseArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, args.arch)?;
    let dir = ctx
        .target_dir
        .join("xtask")
        .join("test")
        .join("rollback")
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
    // A pack of the default-init bundle signs the sysroot, whose kernel and
    // bundle the `raised` boot signs again.
    let booted = crate::disk::create_disk_image_for(ctx, args.arch, layout, Harness::Init)
        .and_then(|()| prepare(ctx, args, &dir))
        .and_then(|cases| {
            // Held until the last boot's QEMU has exited.
            let _host = crate::host_lock::admit_boot(ctx, &args.host, args.cpus, 1)?;
            let firmware = Firmware::prepare(ctx, args.arch)?;
            // One store for the three boots, removed after the last.
            let vars = firmware.launch_vars()?;
            for case in &cases
            {
                step(&format!("rollback test: {}: booting", case.name));
                boot_case(ctx, args, layout, &dir, case, &firmware, vars.path())
                    .with_context(|| format!("rollback test: {}", case.name))?;
                step(&format!("rollback test: {}: PASS", case.name));
            }
            Ok(())
        });
    // Restore first, and surface its failure ahead of the boots': images
    // carrying a bootloader of another floor would fail every later boot.
    crate::disk::create_disk_image(ctx, args.arch, layout)
        .context("packing the disk images again from the sysroot")?;
    booted.with_context(|| format!("rollback test: FAIL (logs under {})", dir.display()))?;
    step("rollback test: PASS (the floor was written, raised, and refused an older bootloader)");
    Ok(())
}

/// The three boots, their objects built under `dir` from the sysroot a pack
/// of the default-init bundle signed.
fn prepare(ctx: &Context, args: &CaseArgs, dir: &Path) -> Result<Vec<Case>>
{
    let signer = Signer::open(ctx, args.arch)?;
    let floor = TrustStore::parse(signer.store())
        .map_err(|e| err!("the build's trust store does not parse ({e:?})"))?
        .security_floor();
    let raised = floor
        .checked_add(1)
        .context("the build's floor is u32::MAX: no floor is above it")?;

    let store = stage(dir, "trust-store.raised", &signer.store_with_floor(raised)?)?;
    step(&format!(
        "rollback test: building a bootloader under the store with the floor {raised}"
    ));
    let mut substitutes = bootloader_under(ctx, args, &store, &dir.join("boot.efi.raised"))?;
    substitutes.push(sub(
        ESP_KERNEL,
        stage(
            dir,
            "kernel.raised",
            &sign_again(&read_sysroot(ctx, KERNEL)?, &signer, raised)?,
        )?,
    ));
    substitutes.push(sub(
        BUNDLE,
        stage(
            dir,
            "bootstrap.bundle.raised",
            &bundle_signed_again(&read_sysroot(ctx, BUNDLE)?, &signer, raised)?,
        )?,
    ));

    Ok(vec![
        Case {
            name: "first",
            substitutes: Vec::new(),
            expect: vec![floor_line(None, floor), raised_line(floor)],
            timeout: BOOTLOADER_TIMEOUT,
        },
        Case {
            name: "raised",
            substitutes,
            expect: vec![floor_line(Some(floor), raised), raised_line(raised)],
            timeout: BOOTLOADER_TIMEOUT,
        },
        Case {
            name: "older",
            substitutes: Vec::new(),
            expect: vec![refusal_line(raised, floor)],
            timeout: BOOTLOADER_TIMEOUT,
        },
    ])
}

/// The bootloader's line of the floors it read (`core/boot/src/rollback.rs`):
/// the machine's, `None` when it has none, and its trust store's.
fn floor_line(machine: Option<u32>, carried: u32) -> String
{
    let machine = machine.map_or_else(|| "none".to_owned(), |floor| floor.to_string());
    format!("boot: security floor: machine {machine}, trust store {carried}")
}

/// The bootloader's line once it has written the floor `to`.
fn raised_line(to: u32) -> String
{
    format!("boot: security floor: machine raised to {to}")
}

/// The bootloader's fatal line refusing itself, the machine's floor
/// `machine` above its trust store's `carried` (`core/boot/src/error.rs`).
fn refusal_line(machine: u32, carried: u32) -> String
{
    format!(
        "{BOOT_FATAL}this bootloader is older than the machine's security floor: machine floor \
         {machine}, trust store floor {carried}"
    )
}

/// `object`, a signed object, signed again by `signer` at
/// `security_version`, with the role set and name of its first record.
///
/// # Errors
/// When `object` is not a signed object, or the errors of
/// [`Signer::sign_at`].
fn sign_again(object: &[u8], signer: &Signer, security_version: u32) -> Result<Vec<u8>>
{
    let parsed = objsig::split(object).map_err(|e| err!("not a signed object ({e:?})"))?;
    let record = parsed
        .records()
        .next()
        .context("a signed object with no record")?;
    let name = std::str::from_utf8(record.attrs.name).context("a signed name not UTF-8")?;
    let roles: RoleSet = record.attrs.roles;
    signer.sign_at(object, roles, name, security_version)
}

/// `bundle` with every entry signed again as [`sign_again`] does, each in
/// place: a record of one signer at another version has the length of the
/// one it replaces.
///
/// # Errors
/// When `bundle` does not parse, an entry is not a signed object, or one
/// signed again is of another length.
fn bundle_signed_again(bundle: &[u8], signer: &Signer, security_version: u32) -> Result<Vec<u8>>
{
    use boot_protocol::bundle as fmt;
    let header =
        fmt::parse_header(bundle).map_err(|e| err!("the bundle does not parse ({e:?})"))?;
    let mut out = bundle.to_vec();
    for index in 0..header.entry_count
    {
        let entry = fmt::entry_at(bundle, index)
            .with_context(|| format!("the bundle has no entry {index}"))?;
        let name = String::from_utf8_lossy(fmt::name_str(&entry.name)).into_owned();
        let start = usize::try_from(entry.offset).context("entry offset past usize")?;
        let end = start
            .checked_add(usize::try_from(entry.size).context("entry size past usize")?)
            .context("entry end past usize")?;
        let object = bundle
            .get(start..end)
            .with_context(|| format!("the entry {name} runs past the bundle"))?;
        let again = sign_again(object, signer, security_version)
            .with_context(|| format!("signing the bundle entry {name} again"))?;
        ensure!(
            again.len() == object.len(),
            "the bundle entry {name} signed again is {} bytes, not {}",
            again.len(),
            object.len()
        );
        if let Some(slot) = out.get_mut(start..end)
        {
            slot.copy_from_slice(&again);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: an owed line that differs from the bootloader's, so a
    // boot that did what it should fails at its deadline, or one that
    // matches a line of another floor.
    #[test]
    fn the_owed_lines_are_the_bootloaders()
    {
        assert_eq!(
            floor_line(None, 1),
            "boot: security floor: machine none, trust store 1"
        );
        assert_eq!(
            floor_line(Some(1), 2),
            "boot: security floor: machine 1, trust store 2"
        );
        assert_eq!(raised_line(2), "boot: security floor: machine raised to 2");
        assert_eq!(
            refusal_line(2, 1),
            "SERAPH BOOT FATAL: this bootloader is older than the machine's security floor: \
             machine floor 2, trust store floor 1"
        );
    }
}
