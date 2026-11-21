// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test/signing.rs

//! Signature refusal test: each verifier of docs/signing.md refuses an object
//! that does not verify, and the boot reports the refusal it is owed.
//!
//! The case boots the current sysroot eight times, each from disk images
//! that carry objects no build makes, written in place of the sysroot's
//! through [`crate::disk::create_disk_image_substituting`]:
//!
//! - `kernel`: the kernel with a body byte flipped; the bootloader refuses
//!   it (`Failed(BodyHash)`).
//! - `bundle`: the `/services/drivers/virtio-blk` entry of the bundle with a
//!   body byte flipped; the bootloader refuses it (`Failed(BodyHash)`).
//! - `policy-missing`: the bundle without its boot-time policy entry,
//!   `/config/boot/policy.conf`; the bootloader refuses the bundle.
//! - `revoked`: a bootloader built under the build's trust store with the
//!   signing key revoked; it refuses the kernel (`Failed(Revoked)`).
//! - `rootfs`: `/services/timed` with a body byte flipped, `/services/pwrmgr`
//!   signed with the data role alone, and `/services/crashd` signed by a key
//!   no anchor trusts; procmgr refuses each (`Failed(BodyHash)`,
//!   `Failed(Role)`, `Untrusted`) and svcmgr reports the refused launch. The kernel and
//!   `/programs/terminal` each carry a record of that untrusted key before
//!   their own, which the bootloader and procmgr skip, and the boot reaches
//!   the terminal's READY line. On riscv64 the platform description table
//!   `/config/devmgr/platform/qemu-virt.platform` has a body byte flipped
//!   too: procmgr refuses it at devmgr's verified read (`Failed(BodyHash)`),
//!   and devmgr passes it over and adds no platform-table record.
//! - `configuration`: a bootloader built under the build's trust store with
//!   two more anchors, one trusted for every role but configuration and one
//!   for configuration alone. In `/config/svcmgr/services/`, `timed.svc` has a
//!   body byte flipped, `pwrmgr.svc` is unsigned, `crashd.svc` is signed by
//!   the first anchor's key, and `oomd.svc` by the second's, which signs
//!   `/services/oomd` as a service too; `entropyd.svc` is validly signed
//!   over another body than the one the index holds, as an older signed copy
//!   is; the directory's index, validly signed, names a `removed.svc` the
//!   directory lacks and omits the `swapd.svc` it holds;
//!   `/config/devmgr/classes/rtc.class` has a body byte flipped. procmgr
//!   refuses each configuration file at svcmgr's verified read
//!   (`Failed(BodyHash)`, `Parse(Magic)`, `Failed(KeyUsage)`) and svcmgr
//!   reports it passed over; svcmgr refuses `entropyd.svc`, whose body does
//!   not match its index line; svcmgr reads `oomd.svc` and procmgr refuses
//!   the service it names (`Failed(KeyUsage)`); svcmgr reports the file the
//!   index names but the directory lacks, and the file it does not name; the
//!   boot reaches the terminal's READY line.
//! - `policy-key`: the `configuration` case's bootloader, and the bundle's
//!   policy entry signed by the key its store trusts for every role but
//!   configuration; the bootloader refuses it (`Failed(KeyUsage)`).
//! - `index`: the indexes of `/config/svcmgr/services/` and
//!   `/config/devmgr/classes/` each with a body byte flipped. procmgr refuses
//!   both (`Failed(BodyHash)`), svcmgr reports that it read no recipe and
//!   configured no class, and every service init registered as one without a
//!   definition.
//!
//! Every boot packs the default-init harness's bundle, which the pack composes
//! from the installed files; the substitutes are written in the images alone.
//! A boot passes when every line it is owed appears; it fails at once on any
//! other refusal or a fatal marker, and at its deadline naming the lines
//! missing ([`Judge`]). Every boot's serial log is saved under
//! `target/xtask/test/signing/<arch>/`. The sysroot is left as it was, apart
//! from the signing every pack does, and the disk images are packed again in
//! the layout they had, with the recorded harness's bundle.
//!
//! Requires a populated sysroot from `cargo xtask build` whose recorded
//! harness is `init` (`cargo xtask mkdisk --harness init`), as the case
//! registry checks.

use std::fs;
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use objsig::{Role, RoleSet};

use crate::arch::Arch;
use crate::bundle::Harness;
use crate::cli::{BuildArgs, BuildComponent};
use crate::commands::test::cases::CaseArgs;
use crate::context::Context;
use crate::disk::{DiskLayout, Substitute};
use crate::error::{Context as _, Result, bail, ensure, err};
use crate::qemu::{
    Firmware, GdbMode, Iommu, QemuDisplay, QemuLaunchSpec, RiscvMmu, RiscvZkr, SecondDisk,
    X86Paging, X86ShadowStack, build_qemu_argv, validate_sysroot_for_launch,
};
use crate::signing::{Config, Signer, os_random, prepend_records};
use crate::util::{require_tool, step};

/// The terminal's line once it reads input. Kept in sync with
/// `programs/terminal/src/main.rs`.
pub(super) const TERMINAL_READY: &str = "terminal: READY for injection";

/// The prefix of the bootloader's fatal line (`core/boot/src/error.rs`).
pub(super) const BOOT_FATAL: &str = "SERAPH BOOT FATAL: ";

/// Text of every refusal line a verifier logs: the bootloader's and
/// procmgr's (`services/procmgr/src/image.rs`), and svcmgr's and init's
/// reports of a refused launch; and of devmgr's refusals of DMA under a
/// required confinement (`services/devmgr/src/bind.rs` and `iommu.rs`).
const REFUSAL_MARKERS: [&str; 3] = [
    "signature verification refused",
    "signature did not verify",
    DMA_REFUSED,
];

/// Text of devmgr's lines refusing a device's driver, and every driver,
/// under the boot policy's required DMA confinement.
pub(super) const DMA_REFUSED: &str = "the boot policy sets dma-confinement = required";

/// Text of a line that ends a boot in failure: the fatal markers of
/// `run --runs`'s default fail pattern. A test harness's own verdict is
/// not one: a staged harness may fail its tests of the services this case
/// refuses.
const DEATH_MARKERS: [&str; 6] = [
    "KERNEL EXCEPTION",
    "FATAL:",
    "PANIC at ",
    "PANIC: ",
    "=== WATCHDOG",
    "entropy: SELFTEST FAIL",
];

/// Budget for a boot the bootloader ends.
pub(super) const BOOTLOADER_TIMEOUT: Duration = Duration::from_mins(3);

/// Budget for the boot that reaches the terminal.
pub(super) const ROOTFS_TIMEOUT: Duration = Duration::from_mins(6);

/// The sysroot-relative paths of the objects the cases read or replace: the
/// installed kernel, its ESP copy, the bundle on the ESP, and installed
/// services and programs.
pub(super) const KERNEL: &str = "boot/kernel";
pub(super) const ESP_KERNEL: &str = "esp/EFI/seraph/kernel";
pub(super) const BUNDLE: &str = "esp/EFI/seraph/bootstrap.bundle";
const TAMPERED: &str = "services/timed";
const WRONG_ROLE: &str = "services/pwrmgr";
const UNTRUSTED: &str = "services/crashd";
const EXTRA_RECORD: &str = "programs/terminal";
/// The platform description table riscv64 installs, which the `rootfs` case
/// tampers with there.
const PLATFORM_TABLE: &str = "config/devmgr/platform/qemu-virt.platform";

/// devmgr's lines once procmgr refuses its read of [`PLATFORM_TABLE`] and it
/// has no other table (`services/devmgr/src/platform.rs`).
const TABLE_REFUSED: &str = "platform table /config/devmgr/platform/qemu-virt.platform: procmgr's \
                             verified read refused it (InvalidData); passed over";
const NO_TABLE: &str = "no platform description table for this machine; no platform-table records";

/// The bundle entry the `bundle` case tampers with.
const BUNDLE_ENTRY: &str = "/services/drivers/virtio-blk";

/// The bundle's boot-time policy entry
/// (`boot_protocol::bundle::POLICY_ENTRY_NAME`).
pub(super) const POLICY: &str = "/config/boot/policy.conf";

/// The bootloader's fatal line for a bundle without [`POLICY`]
/// (`core/boot/src/error.rs` and `verify_bundle` in `core/boot/src/main.rs`).
const POLICY_MISSING: &str = "SERAPH BOOT FATAL: bootstrap.bundle is malformed or missing: bundle \
                              missing `/config/boot/policy.conf` entry";

/// The configuration directories svcmgr reads through their indexes, and
/// the files of them the `configuration` case replaces.
const SERVICES_DIR: &str = "config/svcmgr/services";
const CLASSES_DIR: &str = "config/devmgr/classes";
const RECIPE_TAMPERED: &str = "timed.svc";
const RECIPE_UNSIGNED: &str = "pwrmgr.svc";
const RECIPE_NOT_CONFIGURATION: &str = "crashd.svc";
const RECIPE_CONFIGURATION_KEY: &str = "oomd.svc";
const SERVICE_CONFIGURATION_KEY: &str = "services/oomd";
const RECIPE_UNINDEXED: &str = "swapd.svc";
const RECIPE_REPLAYED: &str = "entropyd.svc";
const RECIPE_REMOVED: &str = "removed.svc";
const CLASS_TAMPERED: &str = "rtc.class";

/// One boot: the files its images carry in place of the sysroot's, the lines
/// it owes, its deadline, and what it types at the bootloader's console.
pub(super) struct Case
{
    pub(super) name: &'static str,
    pub(super) substitutes: Vec<Substitute>,
    pub(super) expect: Vec<String>,
    pub(super) timeout: Duration,
    /// The line typed, then Enter, once the bootloader asks to confirm a
    /// trust request ([`CONFIRM_PROMPT`]); `None` types nothing, and the
    /// boot's console input is closed.
    pub(super) answer: Option<&'static str>,
}

/// Text of the bootloader's line asking the console to confirm a trust
/// request. Kept in sync with `core/boot/src/enrolment.rs`.
pub(super) const CONFIRM_PROMPT: &str = "type yes and Enter within 60 seconds";

pub fn run(ctx: &Context, args: &CaseArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, args.arch)?;
    let dir = ctx
        .target_dir
        .join("xtask")
        .join("test")
        .join("signing")
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
    // A pack of the default-init bundle signs the sysroot, whose signed
    // objects the cases derive theirs from, and composes the bundle the
    // `bundle` case tampers with.
    let cases = crate::disk::create_disk_image_for(ctx, args.arch, layout, Harness::Init)
        .and_then(|()| prepare(ctx, args, &dir));
    let results = cases.and_then(|cases| {
        // Held until the last boot's QEMU has exited.
        let _host = crate::host_lock::admit_boot(ctx, &args.host, args.cpus, 1)?;
        let firmware = Firmware::prepare(ctx, args.arch)?;
        Ok(cases
            .iter()
            .map(|case| {
                // Each boot on a variable store of its own.
                let booted = firmware.launch_vars().and_then(|vars| {
                    step(&format!("signature test: {}: booting", case.name));
                    boot_case(ctx, args, layout, &dir, case, &firmware, vars.path())
                });
                (case.name, booted)
            })
            .collect::<Vec<_>>())
    });
    // Restore first, and surface its failure ahead of the boots': images
    // carrying refused objects would fail every later boot.
    crate::disk::create_disk_image(ctx, args.arch, layout)
        .context("packing the disk images again from the sysroot")?;
    let mut failed = Vec::new();
    for (name, result) in results?
    {
        match result
        {
            Ok(()) => step(&format!("signature test: {name}: PASS")),
            Err(e) =>
            {
                step(&format!("signature test: {name}: FAIL: {e:#}"));
                failed.push(name);
            }
        }
    }
    if !failed.is_empty()
    {
        bail!(
            "signature test: {} failed (logs under {})",
            failed.join(", "),
            dir.display()
        );
    }
    step("signature test: PASS (every verifier refused what it was owed to refuse)");
    Ok(())
}

/// Build every case's objects under `dir`, from the sysroot a pack of the
/// default-init bundle signed and the bundle it composed.
fn prepare(ctx: &Context, args: &CaseArgs, dir: &Path) -> Result<Vec<Case>>
{
    let signer = Signer::open(ctx, args.arch)?;
    let kernel = read_sysroot(ctx, KERNEL)?;
    let init_bundle = read_sysroot(ctx, BUNDLE)?;
    let kernel_case = Case {
        name: "kernel",
        substitutes: vec![sub(
            ESP_KERNEL,
            stage(dir, "kernel.tampered", &flip_body_byte(&kernel)?)?,
        )],
        expect: vec![boot_refusal("kernel", "Failed(BodyHash)")],
        timeout: BOOTLOADER_TIMEOUT,
        answer: None,
    };
    let bundle_case = Case {
        name: "bundle",
        substitutes: vec![sub(
            BUNDLE,
            stage(
                dir,
                "bootstrap.bundle.tampered",
                &flip_bundle_entry(&init_bundle, BUNDLE_ENTRY)?,
            )?,
        )],
        expect: vec![boot_refusal(BUNDLE_ENTRY, "Failed(BodyHash)")],
        timeout: BOOTLOADER_TIMEOUT,
        answer: None,
    };
    let policy_missing = Case {
        name: "policy-missing",
        substitutes: vec![sub(
            BUNDLE,
            bundle_with_policy(dir, "bootstrap.bundle.no-policy", &init_bundle, None)?,
        )],
        expect: vec![POLICY_MISSING.to_owned()],
        timeout: BOOTLOADER_TIMEOUT,
        answer: None,
    };
    let scoped = role_scoped(ctx, args, dir, &signer)?;
    Ok(vec![
        kernel_case,
        bundle_case,
        policy_missing,
        revoked_case(ctx, args, dir, &signer)?,
        rootfs_case(ctx, args.arch, dir, &signer)?,
        configuration_case(ctx, dir, &signer, &scoped)?,
        policy_key_case(dir, &init_bundle, &scoped)?,
        index_case(ctx, dir)?,
    ])
}

/// A bootloader whose store trusts two keys beyond the build's, and those
/// keys' signers.
struct RoleScoped
{
    /// Trusted for every role but configuration.
    others: Signer,
    /// Trusted for configuration alone.
    configuration: Signer,
    /// The bootloader, as the substitute of both ESP copies of the
    /// installed one.
    bootloader: Vec<Substitute>,
}

/// Build the [`RoleScoped`] bootloader under the build's store, whose
/// `signer` signs the store, in `dir`.
fn role_scoped(ctx: &Context, args: &CaseArgs, dir: &Path, signer: &Signer) -> Result<RoleScoped>
{
    let others = untrusted_signer(ctx, args.arch)?;
    let configuration = untrusted_signer(ctx, args.arch)?;
    let all_but: Vec<Role> = Role::ALL
        .into_iter()
        .filter(|&role| role != Role::Configuration)
        .collect();
    let store = signer.store_trusting(&[
        (&others, RoleSet::of(&all_but)),
        (&configuration, RoleSet::of(&[Role::Configuration])),
    ])?;
    step("signature test: building a bootloader under a store with role-scoped anchors");
    let store = stage(dir, "trust-store.role-scoped", &store)?;
    let bootloader = bootloader_under(ctx, args, &store, &dir.join("boot.efi.role-scoped"))?;
    Ok(RoleScoped {
        others,
        configuration,
        bootloader,
    })
}

/// The `policy-key` case: the [`RoleScoped`] bootloader, and `bundle` with
/// its policy entry signed in the configuration role by the key that
/// bootloader's store trusts for every role but configuration.
fn policy_key_case(dir: &Path, bundle: &[u8], scoped: &RoleScoped) -> Result<Case>
{
    let entries = crate::bundle::parse_entries(bundle)?;
    let (_, policy) = entries
        .iter()
        .find(|(name, _)| name == POLICY)
        .with_context(|| format!("the bundle holds no entry {POLICY}"))?;
    let foreign = scoped.others.sign(
        crate::signing::body_of(policy)?,
        RoleSet::of(&[Role::Configuration]),
        POLICY,
    )?;
    let mut substitutes = scoped.bootloader.clone();
    substitutes.push(sub(
        BUNDLE,
        bundle_with_policy(dir, "bootstrap.bundle.policy-key", bundle, Some(&foreign))?,
    ));
    Ok(Case {
        name: "policy-key",
        substitutes,
        expect: vec![boot_refusal(POLICY, "Failed(KeyUsage)")],
        timeout: BOOTLOADER_TIMEOUT,
        answer: None,
    })
}

/// Write to `dir/name` the bundle `bundle` with its [`POLICY`] entry
/// replaced by `policy`, or left out when `policy` is `None`, every other
/// entry as it was; returns its path.
///
/// # Errors
/// When `bundle` does not parse or holds no [`POLICY`] entry, or the
/// write fails.
pub(super) fn bundle_with_policy(
    dir: &Path,
    name: &str,
    bundle: &[u8],
    policy: Option<&[u8]>,
) -> Result<PathBuf>
{
    let entries = crate::bundle::parse_entries(bundle)?;
    ensure!(
        entries.iter().any(|(entry, _)| entry == POLICY),
        "the bundle holds no entry {POLICY}"
    );
    let kept: Vec<(String, Vec<u8>)> = entries
        .into_iter()
        .filter_map(|(entry, body)| {
            if entry != POLICY
            {
                return Some((entry, body.to_vec()));
            }
            policy.map(|policy| (entry, policy.to_vec()))
        })
        .collect();
    let count = u32::try_from(kept.len()).context("entry count past u32")?;
    let path = dir.join(name);
    crate::bundle::write_bundle(&path, count, &kept)?;
    Ok(path)
}

/// The `revoked` case: a bootloader built under the build's store with
/// `signer`'s key revoked, in place of both ESP copies of the installed one.
fn revoked_case(ctx: &Context, args: &CaseArgs, dir: &Path, signer: &Signer) -> Result<Case>
{
    let revoking = stage(
        dir,
        "trust-store.revoking",
        &signer.store_revoking_own_key()?,
    )?;
    step("signature test: building a bootloader under a store revoking the signing key");
    Ok(Case {
        name: "revoked",
        substitutes: bootloader_under(ctx, args, &revoking, &dir.join("boot.efi.revoking"))?,
        expect: vec![boot_refusal("kernel", "Failed(Revoked)")],
        timeout: BOOTLOADER_TIMEOUT,
        answer: None,
    })
}

/// Build a bootloader embedding the trust store at `store` into `boot`, and
/// return it as the substitute of both ESP copies of the installed one.
pub(super) fn bootloader_under(
    ctx: &Context,
    args: &CaseArgs,
    store: &Path,
    boot: &Path,
) -> Result<Vec<Substitute>>
{
    let build = BuildArgs {
        arch: args.arch,
        release: args.release,
        component: BuildComponent::Boot,
        debug: Vec::new(),
        // The lint pass is the build's; this compiles the tree it checked.
        skip_lints: true,
        host: args.host.common.clone(),
    };
    // The case boots, so `main` admitted no build: the compile is admitted
    // here, as a build.
    crate::host_lock::admit_build(ctx, &args.host.common)?;
    crate::commands::build::compile_boot(ctx, &build, store, boot)?;
    let mut substitutes = Vec::new();
    for image in crate::esp::bootloader_copies(ctx, args.arch)
    {
        let relative = image
            .strip_prefix(&ctx.sysroot)
            .with_context(|| format!("{} is outside the sysroot", image.display()))?;
        substitutes.push(Substitute {
            path: relative.to_path_buf(),
            source: boot.to_path_buf(),
        });
    }
    Ok(substitutes)
}

/// The `configuration` case: a bootloader whose store trusts two more keys,
/// one for every role but configuration and one for configuration alone;
/// recipes and a class file refused for a tampered body, no signature, or a
/// key not trusted for configuration; a recipe signed by the
/// configuration-only key, accepted, naming a service that key signed,
/// refused; a recipe signed by `signer` over a body other than the one the
/// index holds, refused; and the services directory's index, signed by
/// `signer`, naming a file the directory lacks and omitting one it holds.
fn configuration_case(
    ctx: &Context,
    dir: &Path,
    signer: &Signer,
    scoped: &RoleScoped,
) -> Result<Case>
{
    let RoleScoped {
        others,
        configuration,
        bootloader,
    } = scoped;
    let config_only = RoleSet::of(&[Role::Configuration]);
    let mut substitutes = bootloader.clone();

    let config_path = |tree: &str, file: &str| format!("{tree}/{file}");
    let resign = |by: &Signer, relative: &str, roles: RoleSet| -> Result<Vec<u8>> {
        let object = read_sysroot(ctx, relative)?;
        by.sign(
            crate::signing::body_of(&object)?,
            roles,
            &install_name(relative),
        )
    };
    let tampered = config_path(SERVICES_DIR, RECIPE_TAMPERED);
    let unsigned = config_path(SERVICES_DIR, RECIPE_UNSIGNED);
    let not_configuration = config_path(SERVICES_DIR, RECIPE_NOT_CONFIGURATION);
    let by_configuration = config_path(SERVICES_DIR, RECIPE_CONFIGURATION_KEY);
    let class = config_path(CLASSES_DIR, CLASS_TAMPERED);
    let replayed = config_path(SERVICES_DIR, RECIPE_REPLAYED);
    let index = config_path(SERVICES_DIR, "index");
    let services = ctx.sysroot.join(SERVICES_DIR);
    let mut names = crate::signing::config_files(&services, ".svc")?
        .context("the sysroot holds no service recipes")?;
    for required in [RECIPE_UNINDEXED, RECIPE_REPLAYED]
    {
        ensure!(
            names.iter().any(|name| name == required),
            "the sysroot holds no {SERVICES_DIR}/{required}"
        );
    }
    names.retain(|name| name != RECIPE_UNINDEXED);
    let mut entries = crate::signing::index_entries(&services, &names)?;
    // The digest of a file the directory lacks is never compared.
    entries.push((RECIPE_REMOVED.to_owned(), objsig::index::body_digest(b"")));
    entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let index_object = signer.sign(
        &crate::signing::index_body(&entries)?,
        config_only,
        &install_name(&index),
    )?;
    // Validly signed, in the configuration role and under its install path,
    // over a body the index does not hold: an older or altered signed copy.
    let replayed_object = {
        let mut body = crate::signing::body_of(&read_sysroot(ctx, &replayed)?)?.to_vec();
        body.extend_from_slice(b"# a body the index was not signed with\n");
        signer.sign(&body, config_only, &install_name(&replayed))?
    };
    let unsigned_body = crate::signing::body_of(&read_sysroot(ctx, &unsigned)?)?.to_vec();
    let staged = [
        (&tampered, flip_body_byte(&read_sysroot(ctx, &tampered)?)?),
        (&unsigned, unsigned_body),
        (
            &not_configuration,
            resign(others, &not_configuration, config_only)?,
        ),
        (
            &by_configuration,
            resign(configuration, &by_configuration, config_only)?,
        ),
        (
            &SERVICE_CONFIGURATION_KEY.to_owned(),
            resign(
                configuration,
                SERVICE_CONFIGURATION_KEY,
                RoleSet::of(&[Role::Service]),
            )?,
        ),
        (&replayed, replayed_object),
        (&class, flip_body_byte(&read_sysroot(ctx, &class)?)?),
        (&index, index_object),
    ];
    for (relative, bytes) in &staged
    {
        // Named for the case: the `index` case stages its own index of the
        // same directory in `dir`.
        let tag = format!("configuration_{}", relative.replace('/', "_"));
        substitutes.push(sub(relative, stage(dir, &tag, bytes)?));
    }

    Ok(Case {
        name: "configuration",
        substitutes,
        expect: configuration_owed(),
        timeout: ROOTFS_TIMEOUT,
        answer: None,
    })
}

/// The lines the `configuration` case owes.
fn configuration_owed() -> Vec<String>
{
    let config_path = |tree: &str, file: &str| format!("{tree}/{file}");
    let tampered = config_path(SERVICES_DIR, RECIPE_TAMPERED);
    let unsigned = config_path(SERVICES_DIR, RECIPE_UNSIGNED);
    let not_configuration = config_path(SERVICES_DIR, RECIPE_NOT_CONFIGURATION);
    let class = config_path(CLASSES_DIR, CLASS_TAMPERED);
    let refused = |relative: &str, refusal: &str| {
        format!(
            "signature verification refused: {}: {refusal}",
            install_name(relative)
        )
    };
    let recipe_dropped = |relative: &str, kind: &str| {
        format!(
            "{}: named by the index, not read ({kind}); dropped",
            install_name(relative)
        )
    };
    let service = install_name(SERVICE_CONFIGURATION_KEY);
    vec![
        refused(&tampered, "Failed(BodyHash)"),
        recipe_dropped(&tampered, "InvalidData"),
        refused(&unsigned, "Parse(Magic)"),
        recipe_dropped(&unsigned, "InvalidData"),
        refused(&not_configuration, "Failed(KeyUsage)"),
        recipe_dropped(&not_configuration, "InvalidData"),
        refused(SERVICE_CONFIGURATION_KEY, "Failed(KeyUsage)"),
        format!("create: {service:?} refused: its signature did not verify"),
        format!(
            "{}: its body is not the one the directory's index was signed with; refused",
            install_name(&config_path(SERVICES_DIR, RECIPE_REPLAYED))
        ),
        recipe_dropped(&config_path(SERVICES_DIR, RECIPE_REPLAYED), "InvalidData"),
        recipe_dropped(&config_path(SERVICES_DIR, RECIPE_REMOVED), "NotFound"),
        format!(
            "{}: not named by the directory's index; not read",
            install_name(&config_path(SERVICES_DIR, RECIPE_UNINDEXED))
        ),
        refused(&class, "Failed(BodyHash)"),
        format!(
            "{}: named by the index, not read (InvalidData); class not configured",
            install_name(&class)
        ),
        TERMINAL_READY.to_owned(),
    ]
}

/// The `index` case: the index of each configuration directory svcmgr reads
/// with a body byte flipped, so svcmgr reads none of its files, reports so,
/// and reports every service init registered as one without a definition.
fn index_case(ctx: &Context, dir: &Path) -> Result<Case>
{
    let mut substitutes = Vec::new();
    let mut expect = Vec::new();
    for (tree, consequence) in [
        (SERVICES_DIR, "no recipe is read"),
        (CLASSES_DIR, "no device class configured"),
    ]
    {
        let index = format!("{tree}/index");
        let tampered = flip_body_byte(&read_sysroot(ctx, &index)?)?;
        substitutes.push(sub(
            &index,
            stage(
                dir,
                &format!("index_{}", index.replace('/', "_")),
                &tampered,
            )?,
        ));
        let name = install_name(&index);
        expect.push(format!(
            "signature verification refused: {name}: Failed(BodyHash)"
        ));
        expect.push(format!("{name} not read (InvalidData); {consequence}"));
    }
    expect.push("svcmgr: registered without definition: ".to_owned());
    Ok(Case {
        name: "index",
        substitutes,
        expect,
        timeout: ROOTFS_TIMEOUT,
        answer: None,
    })
}

/// The `rootfs` case: three services procmgr refuses, and the kernel and
/// the terminal each with an untrusted record before their own; on riscv64
/// also the platform description table, tampered, which procmgr refuses at
/// devmgr's verified read.
fn rootfs_case(ctx: &Context, arch: Arch, dir: &Path, signer: &Signer) -> Result<Case>
{
    let untrusted = untrusted_signer(ctx, arch)?;
    let foreign_record = |relative: &str, object: &[u8], role: Role| -> Result<Vec<u8>> {
        let body = crate::signing::body_of(object)?;
        let theirs = untrusted.sign(body, RoleSet::of(&[role]), &install_name(relative))?;
        prepend_records(object, &theirs)
    };
    let tampered = flip_body_byte(&read_sysroot(ctx, TAMPERED)?)?;
    let pwrmgr = read_sysroot(ctx, WRONG_ROLE)?;
    let as_data = signer.sign(
        crate::signing::body_of(&pwrmgr)?,
        RoleSet::of(&[Role::Data]),
        &install_name(WRONG_ROLE),
    )?;
    let crashd = read_sysroot(ctx, UNTRUSTED)?;
    let foreign = untrusted.sign(
        crate::signing::body_of(&crashd)?,
        RoleSet::of(&[Role::Service]),
        &install_name(UNTRUSTED),
    )?;
    let kernel = foreign_record("kernel", &read_sysroot(ctx, KERNEL)?, Role::Kernel)?;
    let terminal = foreign_record(
        EXTRA_RECORD,
        &read_sysroot(ctx, EXTRA_RECORD)?,
        Role::Program,
    )?;
    let mut expect = Vec::new();
    for (path, refusal) in [
        (TAMPERED, "Failed(BodyHash)"),
        (WRONG_ROLE, "Failed(Role)"),
        (UNTRUSTED, "Untrusted"),
    ]
    {
        let name = install_name(path);
        expect.push(format!("signature verification refused: {name}: {refusal}"));
        expect.push(format!(
            "create: {name:?} refused: its signature did not verify"
        ));
    }
    expect.push(TERMINAL_READY.to_owned());
    let mut substitutes = vec![
        sub(ESP_KERNEL, stage(dir, "kernel.two-records", &kernel)?),
        sub(TAMPERED, stage(dir, "timed.tampered", &tampered)?),
        sub(WRONG_ROLE, stage(dir, "pwrmgr.data", &as_data)?),
        sub(UNTRUSTED, stage(dir, "crashd.untrusted", &foreign)?),
        sub(EXTRA_RECORD, stage(dir, "terminal.two-records", &terminal)?),
    ];
    if arch == Arch::Riscv64
    {
        let table = flip_body_byte(&read_sysroot(ctx, PLATFORM_TABLE)?)?;
        substitutes.push(sub(
            PLATFORM_TABLE,
            stage(dir, "platform-table.tampered", &table)?,
        ));
        expect.push(format!(
            "signature verification refused: {}: Failed(BodyHash)",
            install_name(PLATFORM_TABLE)
        ));
        expect.push(TABLE_REFUSED.to_owned());
        expect.push(NO_TABLE.to_owned());
    }
    Ok(Case {
        name: "rootfs",
        substitutes,
        expect,
        timeout: ROOTFS_TIMEOUT,
        answer: None,
    })
}

/// The bytes of the sysroot file at `relative`.
pub(super) fn read_sysroot(ctx: &Context, relative: &str) -> Result<Vec<u8>>
{
    let path = ctx.sysroot.join(relative);
    fs::read(&path).with_context(|| format!("reading {}", path.display()))
}

/// Write `bytes` to `dir/name`; returns its path.
pub(super) fn stage(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf>
{
    let path = dir.join(name);
    fs::write(&path, bytes).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// The substitute of `source` for the sysroot file at `path`.
pub(super) fn sub(path: &str, source: PathBuf) -> Substitute
{
    Substitute {
        path: PathBuf::from(path),
        source,
    }
}

/// A signer of a local identity no anchor of the build's store holds,
/// generated in a fresh directory outside the work tree, which a signing
/// identity may not be under, and removed again.
pub(super) fn untrusted_signer(ctx: &Context, arch: Arch) -> Result<Signer>
{
    let dir = std::env::temp_dir().join(format!("seraph-test-signing-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let config = Config {
        dir: dir.clone(),
        signer: None,
        deployer_store: None,
    };
    let signer = Signer::new(&config, &ctx.root, arch, &mut os_random);
    let _ = fs::remove_dir_all(&dir);
    signer
}

/// The name the object at the sysroot-relative `path` is signed under: its
/// install path.
fn install_name(path: &str) -> String
{
    if path == "kernel"
    {
        return path.to_owned();
    }
    format!("/{path}")
}

/// The bootloader's fatal line for `object` refused with `refusal`.
fn boot_refusal(object: &str, refusal: &str) -> String
{
    format!("{BOOT_FATAL}signature verification refused: {object}: {refusal}")
}

/// `object`, a signed object, with the middle byte of its body inverted and
/// its trailer as it was.
///
/// # Errors
/// When `object` is not a signed object or its body is empty.
fn flip_body_byte(object: &[u8]) -> Result<Vec<u8>>
{
    let body = crate::signing::body_of(object)?.len();
    ensure!(body > 0, "the object's body is empty");
    let mut out = object.to_vec();
    if let Some(byte) = out.get_mut(body / 2)
    {
        *byte ^= 0xFF;
    }
    Ok(out)
}

/// `bundle` with the body of its entry `name`, a signed object, tampered as
/// [`flip_body_byte`] does.
///
/// # Errors
/// When `bundle` does not parse, holds no entry `name`, or that entry is
/// not a signed object.
fn flip_bundle_entry(bundle: &[u8], name: &str) -> Result<Vec<u8>>
{
    use boot_protocol::bundle as fmt;
    let header =
        fmt::parse_header(bundle).map_err(|e| err!("the bundle does not parse ({e:?})"))?;
    let entry = (0..header.entry_count)
        .filter_map(|index| fmt::entry_at(bundle, index))
        .find(|entry| fmt::name_str(&entry.name) == name.as_bytes())
        .with_context(|| format!("the bundle holds no entry {name}"))?;
    let start = usize::try_from(entry.offset).context("entry offset past usize")?;
    let end = start
        .checked_add(usize::try_from(entry.size).context("entry size past usize")?)
        .context("entry end past usize")?;
    let object = bundle
        .get(start..end)
        .with_context(|| format!("the entry {name} runs past the bundle"))?;
    let flipped = flip_body_byte(object)?;
    let mut out = bundle.to_vec();
    if let Some(slot) = out.get_mut(start..end)
    {
        slot.copy_from_slice(&flipped);
    }
    Ok(out)
}

/// What a boot's serial lines show so far.
#[derive(Debug)]
struct Judge
{
    /// The lines owed, and whether each has appeared.
    owed: Vec<(String, bool)>,
}

/// What a line decides.
#[derive(Debug, PartialEq, Eq)]
enum Verdict
{
    /// Lines are still owed.
    Pending,
    /// Every owed line has appeared.
    Pass,
    /// The line is a refusal not owed, or a fatal marker.
    Fail(String),
}

impl Judge
{
    fn new(owed: &[String]) -> Self
    {
        Self {
            owed: owed.iter().map(|line| (line.clone(), false)).collect(),
        }
    }

    /// Judge the next serial line. A line that holds an owed one counts
    /// before the markers are read, so an owed fatal line is not a death.
    fn line(&mut self, line: &str) -> Verdict
    {
        let mut owed_here = false;
        for (want, seen) in &mut self.owed
        {
            if line.contains(want.as_str())
            {
                *seen = true;
                owed_here = true;
            }
        }
        if !owed_here
        {
            if REFUSAL_MARKERS.iter().any(|m| line.contains(m))
            {
                return Verdict::Fail(format!("a refusal not owed: {}", line.trim()));
            }
            if DEATH_MARKERS.iter().any(|m| line.contains(m))
            {
                return Verdict::Fail(format!("a fatal line: {}", line.trim()));
            }
        }
        if self.owed.iter().all(|(_, seen)| *seen)
        {
            Verdict::Pass
        }
        else
        {
            Verdict::Pending
        }
    }

    /// The owed lines that have not appeared.
    fn missing(&self) -> Vec<&str>
    {
        self.owed
            .iter()
            .filter(|(_, seen)| !seen)
            .map(|(line, _)| line.as_str())
            .collect()
    }
}

/// Pack `case`'s images, boot them on `firmware` with the variable store
/// `vars`, judge the serial lines, and kill QEMU.
pub(super) fn boot_case(
    ctx: &Context,
    args: &CaseArgs,
    layout: DiskLayout,
    dir: &Path,
    case: &Case,
    firmware: &Firmware,
    vars: &Path,
) -> Result<()>
{
    boot_case_on(
        ctx,
        args,
        layout,
        dir,
        case,
        firmware,
        vars,
        Iommu::Attached,
    )
}

/// [`boot_case`] on a machine with the IOMMU `iommu`.
#[expect(
    clippy::too_many_arguments,
    reason = "boot_case's arguments and the machine's IOMMU, each a separate input of the launch"
)]
pub(super) fn boot_case_on(
    ctx: &Context,
    args: &CaseArgs,
    layout: DiskLayout,
    dir: &Path,
    case: &Case,
    firmware: &Firmware,
    vars: &Path,
    iommu: Iommu,
) -> Result<()>
{
    crate::disk::create_disk_image_substituting(
        ctx,
        args.arch,
        layout,
        Harness::Init,
        &case.substitutes,
    )?;
    let log_path = dir.join(format!("{}.log", case.name));
    let mut log =
        fs::File::create(&log_path).with_context(|| format!("creating {}", log_path.display()))?;
    let input = if case.answer.is_some()
    {
        Stdio::piped()
    }
    else
    {
        Stdio::null()
    };
    let mut child = launch(ctx, args, layout, firmware, vars, input, iommu)?;
    let stdout = child.stdout.take().context("QEMU stdout unavailable")?;
    // The serial console's input, held open until QEMU is killed: the judge
    // writes the answer once the prompt appears.
    let mut console = child.stdin.take().zip(case.answer);
    // Serial lines on a worker thread, so the judge has a deadline. Bytes
    // that are not UTF-8 are read lossily rather than ending the stream.
    let (tx, rx) = mpsc::channel::<String>();
    let reader = thread::spawn(move || {
        let mut serial = BufReader::new(stdout);
        let mut raw = Vec::new();
        loop
        {
            raw.clear();
            match serial.read_until(b'\n', &mut raw)
            {
                Ok(0) | Err(_) => break,
                Ok(_) =>
                {
                    if tx.send(String::from_utf8_lossy(&raw).into_owned()).is_err()
                    {
                        break;
                    }
                }
            }
        }
    });
    let result = judge_serial(&rx, &mut log, case, &mut console);
    let _ = child.kill();
    let _ = child.wait();
    // The rest of the stream, after the kill, still goes to the log.
    for line in &rx
    {
        let _ = log.write_all(line.as_bytes());
    }
    let _ = reader.join();
    result.with_context(|| format!("serial log {}", log_path.display()))
}

/// Judge the lines `rx` delivers against `case`, copying each to `log`,
/// until it passes, fails, its deadline passes, or the stream ends. On the
/// bootloader's confirmation prompt, write the answer of `console` to its
/// input, then Enter.
fn judge_serial(
    rx: &mpsc::Receiver<String>,
    log: &mut fs::File,
    case: &Case,
    console: &mut Option<(std::process::ChildStdin, &str)>,
) -> Result<()>
{
    let mut judge = Judge::new(&case.expect);
    let deadline = Instant::now()
        .checked_add(case.timeout)
        .context("a deadline past the clock's range")?;
    loop
    {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left)
        {
            Ok(line) =>
            {
                let _ = log.write_all(line.as_bytes());
                if line.contains(CONFIRM_PROMPT)
                    && let Some((input, answer)) = console.as_mut()
                {
                    // A failed write leaves the prompt unanswered, which the
                    // judge reports as the line it is then owed.
                    let _ = input
                        .write_all(format!("{answer}\r").as_bytes())
                        .and_then(|()| input.flush());
                }
                match judge.line(&line)
                {
                    Verdict::Pending =>
                    {}
                    Verdict::Pass => return Ok(()),
                    Verdict::Fail(why) => bail!("{why}"),
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) =>
            {
                bail!(
                    "missing after {}s: {:?}",
                    case.timeout.as_secs(),
                    judge.missing()
                );
            }
            Err(mpsc::RecvTimeoutError::Disconnected) =>
            {
                bail!("QEMU exited; missing: {:?}", judge.missing());
            }
        }
    }
}

/// Start QEMU on the images of `layout`, `firmware`, the variable store
/// `vars` and the IOMMU `iommu`, its serial stream on its stdout and its
/// serial input `input`.
fn launch(
    ctx: &Context,
    args: &CaseArgs,
    layout: DiskLayout,
    firmware: &Firmware,
    vars: &Path,
    input: Stdio,
    iommu: Iommu,
) -> Result<std::process::Child>
{
    let disk_path = ctx.disk_image();
    let data_image = layout.second_image(ctx);
    let spec = QemuLaunchSpec {
        arch: args.arch,
        disk_path: &disk_path,
        disk_block_size: crate::disk::logical_block_size(&disk_path)?,
        second_disk: data_image
            .as_deref()
            .map(SecondDisk::of_image)
            .transpose()?,
        firmware_code_path: &firmware.code,
        firmware_vars_path: vars,
        smm: firmware.smm,
        cpus: args.cpus,
        threads_per_core: 1,
        mem_mib: args.mem,
        display: QemuDisplay::Headless,
        gdb: GdbMode::Off,
        qmp_socket: None,
        vmgenid_guid: Some("auto"),
        incoming: None,
        riscv_mmu: RiscvMmu::Sv48,
        riscv_zkr: RiscvZkr::On,
        x86_paging: X86Paging::Four,
        x86_shadow_stack: X86ShadowStack::Off,
        iommu,
        debug_port: None,
        test_devices: false,
        hotplug_port: None,
    };
    let qemu_args = build_qemu_argv(&spec)?;
    let qemu_binary = require_tool(args.arch.qemu_binary())?;
    Command::new(&qemu_binary)
        .args(&qemu_args)
        .stdin(input)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning {}", args.arch.qemu_binary()))
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn owed(lines: &[&str]) -> Vec<String>
    {
        lines.iter().map(|&line| line.to_owned()).collect()
    }

    // Defect caught: a judge that passes before every owed line appears, or
    // that needs them in one order when the services' logs interleave.
    #[test]
    fn every_owed_line_in_any_order_passes()
    {
        let mut judge = Judge::new(&owed(&["b refused", "a ready"]));
        assert_eq!(judge.line("boot noise"), Verdict::Pending);
        assert_eq!(judge.line("[x] a ready\n"), Verdict::Pending);
        assert_eq!(judge.missing(), ["b refused"]);
        assert_eq!(judge.line("[y] b refused"), Verdict::Pass);
    }

    // Defect caught: a refusal of an object the case left intact passed over,
    // which would hide a verifier refusing a good object.
    #[test]
    fn a_refusal_not_owed_fails()
    {
        let mut judge = Judge::new(&owed(&[&boot_refusal("kernel", "Failed(BodyHash)")]));
        let Verdict::Fail(why) =
            judge.line("signature verification refused: /services/vfsd: Untrusted")
        else
        {
            panic!("an unowed refusal passed");
        };
        assert!(why.contains("/services/vfsd"));
        let mut judge = Judge::new(&owed(&["x"]));
        assert!(matches!(
            judge.line("create: \"/services/logd\" refused: its signature did not verify"),
            Verdict::Fail(_)
        ));
    }

    // Defect caught: the owed fatal line of the bootloader judged a death, or
    // another fatal line or a panic passed over.
    #[test]
    fn an_owed_fatal_line_passes_and_any_other_fails()
    {
        let fatal = boot_refusal("kernel", "Failed(Revoked)");
        assert_eq!(Judge::new(&owed(&[&fatal])).line(&fatal), Verdict::Pass);
        for line in [
            "SERAPH BOOT FATAL: no supported RISC-V paging mode",
            "KERNEL PANIC at core/kernel/src/mm.rs:10",
            "KERNEL EXCEPTION: page fault",
        ]
        {
            assert!(
                matches!(Judge::new(&owed(&[&fatal])).line(line), Verdict::Fail(_)),
                "{line}"
            );
        }
    }

    // Defect caught: a death marker of the default fail pattern missing from
    // the list (or one the pattern lacks), so a fatal boot is not judged one.
    #[test]
    fn death_markers_agree_with_the_default_fail_pattern()
    {
        let fail = crate::regex::Regex::new(crate::cli::DEFAULT_FAIL_REGEX).unwrap();
        for marker in DEATH_MARKERS
        {
            assert!(fail.is_match(marker), "{marker}");
        }
        // `PANIC( at |: )` stands for two markers, which the list holds.
        let plain = crate::cli::DEFAULT_FAIL_REGEX.replace("PANIC( at |: )", "PANIC at ");
        assert!(DEATH_MARKERS.contains(&"PANIC: "));
        for alternative in plain.split('|')
        {
            assert!(
                alternative.starts_with("SOME TESTS") || DEATH_MARKERS.contains(&alternative),
                "{alternative}"
            );
        }
    }

    /// A signed object of `body`, signed by a throwaway identity.
    fn signed(body: &[u8]) -> Vec<u8>
    {
        let root = crate::signing::testing::scratch("test-signing");
        let signer = crate::signing::testing::signer(&root.join("keys"), Arch::X86_64);
        let object = signer
            .sign(body, RoleSet::of(&[Role::Service]), "/services/x")
            .unwrap();
        let _ = fs::remove_dir_all(&root);
        object
    }

    // Defect caught: a tamper that touches the trailer, so the boot refuses
    // for a parse error rather than the body hash the case owes, or one that
    // changes nothing.
    #[test]
    fn a_flipped_body_byte_leaves_the_trailer_alone()
    {
        let object = signed(b"\x7fELF body bytes");
        let flipped = flip_body_byte(&object).unwrap();
        let (body, before) = object.split_at(17);
        let (new_body, after) = flipped.split_at(17);
        assert_eq!(before, after);
        assert_ne!(body, new_body);
        assert_eq!(body.iter().zip(new_body).filter(|(a, b)| a != b).count(), 1);
    }

    // Defect caught: the tamper landing on another entry or on the bundle's
    // headers, so the bootloader refuses another object or the bundle's
    // format.
    #[test]
    fn a_tampered_bundle_entry_changes_that_entry_alone()
    {
        use boot_protocol::bundle as fmt;
        let first = signed(b"\x7fELF first");
        let second = signed(b"\x7fELF second");
        let align = usize::try_from(fmt::BODY_ALIGNMENT).unwrap();
        // Each body in its own aligned slot, after the headers' slot.
        let slot = first.len().max(second.len()).next_multiple_of(align);
        let mut bundle = vec![0u8; align + 2 * slot];
        bundle[..8].copy_from_slice(&fmt::MAGIC);
        bundle[8..12].copy_from_slice(&fmt::VERSION.to_le_bytes());
        bundle[12..16].copy_from_slice(&2u32.to_le_bytes());
        for (index, (name, object)) in [("init", &first), (BUNDLE_ENTRY, &second)]
            .into_iter()
            .enumerate()
        {
            let at = fmt::HEADER_SIZE + index * fmt::ENTRY_HEADER_SIZE;
            bundle[at..at + name.len()].copy_from_slice(name.as_bytes());
            let offset = align + index * slot;
            let fields = at + fmt::ENTRY_NAME_LEN;
            bundle[fields..fields + 8].copy_from_slice(&(offset as u64).to_le_bytes());
            bundle[fields + 8..fields + 16].copy_from_slice(&(object.len() as u64).to_le_bytes());
            bundle[offset..offset + object.len()].copy_from_slice(object);
        }
        let tampered = flip_bundle_entry(&bundle, BUNDLE_ENTRY).unwrap();
        let entry = fmt::entry_at(&tampered, 1).unwrap();
        let start = usize::try_from(entry.offset).unwrap();
        let end = start + usize::try_from(entry.size).unwrap();
        assert_eq!(tampered[start..end], flip_body_byte(&second).unwrap());
        assert_eq!(tampered[..start], bundle[..start]);
        assert_eq!(tampered[end..], bundle[end..]);
        flip_bundle_entry(&bundle, "absent").unwrap_err();
    }

    // Defect caught: the case's policy name drifting from the one the
    // bootloader requires, so `policy-missing` drops another entry and
    // `policy-key` signs one the bootloader does not check as the policy.
    #[test]
    fn the_policy_name_is_the_bootloader_s()
    {
        assert_eq!(POLICY.as_bytes(), boot_protocol::bundle::POLICY_ENTRY_NAME);
        assert!(POLICY_MISSING.starts_with(BOOT_FATAL));
        assert!(POLICY_MISSING.ends_with(&format!("bundle missing `{POLICY}` entry")));
    }

    // Defect caught: a rewritten bundle that loses, reorders or alters an
    // entry other than the policy, or keeps the policy it was told to drop.
    #[test]
    fn a_bundle_with_another_policy_changes_that_entry_alone()
    {
        let root = crate::signing::testing::scratch("test-signing-policy");
        fs::create_dir_all(&root).unwrap();
        let entries = vec![
            ("init".to_owned(), signed(b"\x7fELF init")),
            (
                POLICY.to_owned(),
                signed(b"dma-confinement = opportunistic\n"),
            ),
            (BUNDLE_ENTRY.to_owned(), signed(b"\x7fELF blk")),
        ];
        let path = root.join("bundle");
        crate::bundle::write_bundle(&path, 3, &entries).unwrap();
        let bundle = fs::read(&path).unwrap();
        let owned = |bytes: &[u8]| -> Vec<(String, Vec<u8>)> {
            crate::bundle::parse_entries(bytes)
                .unwrap()
                .into_iter()
                .map(|(name, body)| (name, body.to_vec()))
                .collect()
        };

        let dropped =
            fs::read(bundle_with_policy(&root, "dropped", &bundle, None).unwrap()).unwrap();
        let mut without = entries.clone();
        without.remove(1);
        assert_eq!(owned(&dropped), without);

        let other = signed(b"dma-confinement = required\n");
        let replaced =
            fs::read(bundle_with_policy(&root, "replaced", &bundle, Some(&other)).unwrap())
                .unwrap();
        let mut with = entries.clone();
        with[1].1.clone_from(&other);
        assert_eq!(owned(&replaced), with);

        bundle_with_policy(&root, "none", &dropped, None).unwrap_err();
        let _ = fs::remove_dir_all(&root);
    }
}
