// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test/dma_confinement.rs

//! Required DMA confinement test: with the boot policy's
//! `dma-confinement = required`, devmgr gives no driver to a DMA-capable
//! device no IOMMU unit confines, and the boot set runs when every device is
//! confined (docs/device-management.md § Required DMA Confinement).
//!
//! The case boots the current sysroot twice, from disk images whose bundle
//! carries, in place of the sysroot's policy, one setting
//! `dma-confinement = required`, signed in the configuration role by the
//! build's signing key:
//!
//! - `absent`: a machine with no IOMMU (`--iommu absent`). devmgr reads the
//!   setting, logs that no DMA-capable device is given a driver, and refuses
//!   each such device's driver, naming the device and the setting; with no
//!   block device vfsd mounts no root, and the boot stops there.
//! - `attached`: the default machine, every `virtio-pci` device behind the
//!   IOMMU. devmgr reads the setting, refuses no device, and the boot reaches
//!   the terminal's READY line.
//!
//! A boot passes when every line it is owed appears, as the `signing` case
//! judges one, and fails on a refusal not owed: a DMA refusal in the
//! `attached` boot is one. Every boot's serial log is saved under
//! `target/xtask/test/dma-confinement/<arch>/`. The sysroot is left as it
//! was, apart from the signing every pack does, and the disk images are
//! packed again in the layout they had, with the recorded harness's bundle.
//!
//! Requires a populated sysroot from `cargo xtask build` whose recorded
//! harness is `init`, as the case registry checks.

use std::fs;
use std::path::Path;

use objsig::RoleSet;

use crate::bundle::Harness;
use crate::commands::test::cases::CaseArgs;
use crate::commands::test::signing::{
    BUNDLE, Case, POLICY, ROOTFS_TIMEOUT, TERMINAL_READY, boot_case_on, bundle_with_policy,
    read_sysroot, sub,
};
use crate::context::Context;
use crate::error::{Context as _, Result, ensure};
use crate::qemu::{Firmware, Iommu, validate_sysroot_for_launch};
use crate::signing::Signer;
use crate::util::step;

/// The body of the policy both boots carry.
const REQUIRED: &[u8] =
    b"# The dma-confinement case's boot-time policy.\ndma-confinement = required\n";

/// devmgr's line once it has read the policy (`services/devmgr/src/decls.rs`).
const POLICY_READ: &str = "boot policy: dma-confinement = required";

/// devmgr's line when no IOMMU confines DMA (`services/devmgr/src/iommu.rs`).
const NO_DRIVER: &str = "no DMA-capable device is given a driver, as the boot policy sets \
                         dma-confinement = required";

/// The tail of devmgr's line refusing one device's driver
/// (`services/devmgr/src/bind.rs`).
const DEVICE_REFUSED: &str = "is confined by no IOMMU unit and the boot policy sets \
                              dma-confinement = required; not bound";

/// vfsd's line when devmgr serves it no block device
/// (`services/vfsd/src/main.rs`).
const NO_BLOCK_DEVICE: &str = "no block device available";

pub fn run(ctx: &Context, args: &CaseArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, args.arch)?;
    let dir = ctx
        .target_dir
        .join("xtask")
        .join("test")
        .join("dma-confinement")
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
    // A pack of the default-init bundle signs the sysroot and composes the
    // bundle whose policy the boots replace.
    let results = crate::disk::create_disk_image_for(ctx, args.arch, layout, Harness::Init)
        .and_then(|()| prepare(ctx, args, &dir))
        .and_then(|boots| {
            // Held until the last boot's QEMU has exited.
            let _host = crate::host_lock::admit_boot(ctx, &args.host, args.cpus, 1)?;
            let firmware = Firmware::prepare(ctx, args.arch)?;
            Ok(boots
                .iter()
                .map(|(case, iommu)| {
                    let booted = firmware.launch_vars().and_then(|vars| {
                        step(&format!("dma-confinement test: {}: booting", case.name));
                        boot_case_on(
                            ctx,
                            args,
                            layout,
                            &dir,
                            case,
                            &firmware,
                            vars.path(),
                            *iommu,
                        )
                    });
                    (case.name, booted)
                })
                .collect::<Vec<_>>())
        });
    // Restore first, and surface its failure ahead of the boots': images
    // carrying another policy would change every later boot.
    crate::disk::create_disk_image(ctx, args.arch, layout)
        .context("packing the disk images again from the sysroot")?;
    let mut failed = Vec::new();
    for (name, result) in results?
    {
        match result
        {
            Ok(()) => step(&format!("dma-confinement test: {name}: PASS")),
            Err(e) =>
            {
                step(&format!("dma-confinement test: {name}: FAIL: {e:#}"));
                failed.push(name);
            }
        }
    }
    ensure!(
        failed.is_empty(),
        "dma-confinement test: {} failed (logs under {})",
        failed.join(", "),
        dir.display()
    );
    step("dma-confinement test: PASS (no unconfined device was given a driver)");
    Ok(())
}

/// The two boots, each with the IOMMU it runs on, their bundle built under
/// `dir` from the one a pack of the default-init bundle composed.
fn prepare(ctx: &Context, args: &CaseArgs, dir: &Path) -> Result<Vec<(Case, Iommu)>>
{
    let signer = Signer::open(ctx, args.arch)?;
    let policy = signer.sign(
        REQUIRED,
        RoleSet::of(&[crate::bundle::entry_role(POLICY)]),
        POLICY,
    )?;
    let bundle = bundle_with_policy(
        dir,
        "bootstrap.bundle.required",
        &read_sysroot(ctx, BUNDLE)?,
        Some(&policy),
    )?;
    let boot = |name, expect: &[&str]| Case {
        name,
        substitutes: vec![sub(BUNDLE, bundle.clone())],
        expect: expect.iter().map(|&line| line.to_owned()).collect(),
        timeout: ROOTFS_TIMEOUT,
        answer: None,
    };
    Ok(vec![
        (
            boot(
                "absent",
                &[POLICY_READ, NO_DRIVER, DEVICE_REFUSED, NO_BLOCK_DEVICE],
            ),
            Iommu::Absent,
        ),
        (
            boot("attached", &[POLICY_READ, TERMINAL_READY]),
            Iommu::Attached,
        ),
    ])
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::commands::test::signing::DMA_REFUSED;

    // Defect caught: a policy the boots carry that devmgr would not read as
    // the required setting, so the case would show the default instead.
    #[test]
    fn the_policy_requires_confinement()
    {
        let policy = boot_policy::parse(REQUIRED).unwrap();
        assert_eq!(
            policy.dma_confinement,
            boot_policy::DmaConfinement::Required
        );
        assert!(POLICY_READ.ends_with(boot_policy::DmaConfinement::Required.value()));
    }

    // Defect caught: an owed refusal line the judge does not hold as a
    // refusal, so the same line in the `attached` boot would pass.
    #[test]
    fn the_owed_refusals_are_refusals_the_judge_fails_unowed()
    {
        for line in [NO_DRIVER, DEVICE_REFUSED]
        {
            assert!(line.contains(DMA_REFUSED), "{line}");
        }
        assert!(!POLICY_READ.contains(DMA_REFUSED));
    }
}
