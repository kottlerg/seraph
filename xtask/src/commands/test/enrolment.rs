// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test/enrolment.rs

//! Root enrolment test: the bootloader enrols, rotates and revokes roots
//! through trust requests on the ESP, keeping them in firmware storage, with
//! no rebuild of the bootloader (docs/signing.md § Trust Store).
//!
//! The case boots six times on one variable store, the firmware's template
//! copied once, so each boot sees the enrolled store the one before it left.
//! `R` is the build's identity, whose roots the bootloader carries; `E` and `F`
//! are local identities generated for the case, which no built-in anchor
//! trusts.
//!
//! - `signed`: a request adding `E`'s root, signed by `R` in the enrolment
//!   role; the bootloader applies it with no one present.
//! - `unanswered`: an unsigned request adding `F`'s root; the bootloader asks
//!   the console, no answer comes, and it refuses the request at the
//!   timeout.
//! - `confirmed`: the same request, answered `yes` at the console; applied.
//! - `commit-refused`: an unsigned request revoking `R`'s roots, with the
//!   sysroot's images, which `R` signed; the kernel would not verify under the
//!   store it gives, so the bootloader refuses it before asking, and boots.
//! - `revoked`: a request revoking `R`'s roots, signed by `E` in the enrolment
//!   role, with the kernel and every bundle entry signed again by `E`; applied.
//! - `holds`: the same request again, with the sysroot's images; the request
//!   changes nothing and is skipped, and the bootloader refuses the kernel
//!   (`Failed(Revoked)`).
//!
//! Every boot owes the line of each anchor with its source, the store's
//! counts, and what it did with the request; a boot that loads owes the
//! bundle's verification. A boot passes as the `signing` case judges one; a
//! boot after a failed one is not made. Every boot's serial log is saved
//! under `target/xtask/test/enrolment/<arch>/`. The sysroot is left as it
//! was, apart from the signing every pack does and a request it staged,
//! which is restored, and the disk images are packed again in the layout
//! they had.
//!
//! Requires a populated sysroot from `cargo xtask build` whose recorded
//! harness is `init`, as the case registry checks.

use std::fs;
use std::path::Path;

use objsig::{KeyId, TrustStore};

use crate::bundle::Harness;
use crate::commands::test::cases::CaseArgs;
use crate::commands::test::rollback::{bundle_signed_again, sign_again};
use crate::commands::test::signing::{
    BOOT_FATAL, BOOTLOADER_TIMEOUT, BUNDLE, CONFIRM_PROMPT, Case, ESP_KERNEL, KERNEL, boot_case,
    read_sysroot, stage, sub, untrusted_signer,
};
use crate::context::Context;
use crate::error::{Context as _, Result, err};
use crate::qemu::{Firmware, validate_sysroot_for_launch};
use crate::signing::{SECURITY_VERSION, Signer, request};
use crate::util::step;

/// The bootloader's line once the bundle has verified (`core/boot/src/main.rs`).
const BUNDLE_VERIFIED: &str = "entries verified";

pub fn run(ctx: &Context, args: &CaseArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, args.arch)?;
    let dir = ctx
        .target_dir
        .join("xtask")
        .join("test")
        .join("enrolment")
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
    let staged = match fs::read(request::staged_path(ctx))
    {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).context("reading the staged trust request"),
    };
    let booted = request::clear(ctx)
        .and_then(|()| crate::disk::create_disk_image_for(ctx, args.arch, layout, Harness::Init))
        .and_then(|()| prepare(ctx, args, &dir))
        .and_then(|boots| {
            // Held until the last boot's QEMU has exited.
            let _host = crate::host_lock::admit_boot(ctx, &args.host, args.cpus, 1)?;
            let firmware = Firmware::prepare(ctx, args.arch)?;
            // One store for the six boots, removed after the last.
            let vars = firmware.launch_vars()?;
            for (request_bytes, case) in &boots
            {
                step(&format!("enrolment test: {}: booting", case.name));
                request::stage(ctx, request_bytes)
                    .and_then(|_| boot_case(ctx, args, layout, &dir, case, &firmware, vars.path()))
                    .with_context(|| format!("enrolment test: {}", case.name))?;
                step(&format!("enrolment test: {}: PASS", case.name));
            }
            Ok(())
        });
    // Restore first, and surface its failure ahead of the boots': an image
    // carrying a request would apply it on every later boot.
    match &staged
    {
        Some(bytes) => request::stage(ctx, bytes).map(|_| ()),
        None => request::clear(ctx),
    }
    .context("restoring the staged trust request")?;
    crate::disk::create_disk_image(ctx, args.arch, layout)
        .context("packing the disk images again from the sysroot")?;
    booted.with_context(|| format!("enrolment test: FAIL (logs under {})", dir.display()))?;
    step(
        "enrolment test: PASS (roots enrolled signed and confirmed, a request refused at the \
         timeout and by the commit rule, the build's roots revoked and the revocation held)",
    );
    Ok(())
}

/// An anchor as the bootloader logs it.
struct Logged
{
    label: String,
    id: KeyId,
    local: bool,
}

/// The anchors of the trust store `bytes`.
fn anchors_of(bytes: &[u8]) -> Result<Vec<Logged>>
{
    let store =
        TrustStore::parse(bytes).map_err(|e| err!("a trust store does not parse ({e:?})"))?;
    Ok(store
        .anchors()
        .map(|anchor| Logged {
            label: anchor.label.to_owned(),
            id: anchor.key_id,
            local: anchor.local,
        })
        .collect())
}

/// The six boots, each with the request it stages, their objects built
/// under `dir` from the sysroot a pack of the default-init bundle signed.
fn prepare(ctx: &Context, args: &CaseArgs, dir: &Path) -> Result<Vec<(Vec<u8>, Case)>>
{
    let build_signer = Signer::open(ctx, args.arch)?;
    let builtin = TrustStore::parse(build_signer.store())
        .map_err(|e| err!("the build's trust store does not parse ({e:?})"))?;
    let floor = builtin.security_floor();
    let revoked_before = builtin.revoked().len();
    let roots = anchors_of(build_signer.store())?;
    let root_ids: Vec<KeyId> = roots.iter().map(|root| root.id).collect();
    let signing_root = *root_ids
        .first()
        .context("the build's trust store holds no anchor")?;
    let enrolled = untrusted_signer(ctx, args.arch)?;
    let confirmed = untrusted_signer(ctx, args.arch)?;
    let e_roots = anchors_of(enrolled.store())?;
    let f_roots = anchors_of(confirmed.store())?;
    let e_root = e_roots
        .first()
        .context("an identity's store holds no anchor")?;
    let f_root = f_roots
        .first()
        .context("an identity's store holds no anchor")?;

    let add_e = request::build(&[enrolled.store().to_vec()], &[], Some(&build_signer))?;
    let add_f = request::build(&[confirmed.store().to_vec()], &[], None)?;
    let revoke_unsigned = request::build(&[], &root_ids, None)?;
    let revoke_by_e = request::build(&[], &root_ids, Some(&enrolled))?;

    // The kernel and every bundle entry signed again by E, for the boot
    // that revokes R.
    let mut resigned = vec![sub(
        ESP_KERNEL,
        stage(
            dir,
            "kernel.enrolled",
            &sign_again(&read_sysroot(ctx, KERNEL)?, &enrolled, SECURITY_VERSION)?,
        )?,
    )];
    resigned.push(sub(
        BUNDLE,
        stage(
            dir,
            "bootstrap.bundle.enrolled",
            &bundle_signed_again(&read_sysroot(ctx, BUNDLE)?, &enrolled, SECURITY_VERSION)?,
        )?,
    ));

    let facts = Facts {
        roots: &roots,
        signing_root,
        e_root,
        f_root,
        floor,
        revoked_before,
    };
    let [signed, unanswered, answered, commit_refused, revoked, holds] = owed(&facts);

    let boot = |name, substitutes, expect, answer| Case {
        name,
        substitutes,
        expect,
        timeout: BOOTLOADER_TIMEOUT,
        answer,
    };
    Ok(vec![
        (add_e, boot("signed", Vec::new(), signed, None)),
        (
            add_f.clone(),
            boot("unanswered", Vec::new(), unanswered, None),
        ),
        (add_f, boot("confirmed", Vec::new(), answered, Some("yes"))),
        (
            revoke_unsigned,
            boot("commit-refused", Vec::new(), commit_refused, Some("yes")),
        ),
        (
            revoke_by_e.clone(),
            boot("revoked", resigned, revoked, None),
        ),
        (revoke_by_e, boot("holds", Vec::new(), holds, None)),
    ])
}

/// What the case knows of the stores: the build's roots, the root that
/// signs the first request, the roots of `E` and `F`, and the built-in
/// store's floor and revoked count.
struct Facts<'a>
{
    roots: &'a [Logged],
    signing_root: KeyId,
    e_root: &'a Logged,
    f_root: &'a Logged,
    floor: u32,
    revoked_before: usize,
}

/// Whether a logged anchor is revoked.
#[derive(Clone, Copy)]
enum Status
{
    Trusted,
    Revoked,
}

/// The lines each of the six boots owes, in their order.
fn owed(facts: &Facts<'_>) -> [Vec<String>; 6]
{
    let built_in = |status: Status| -> Vec<String> {
        facts
            .roots
            .iter()
            .map(|root| anchor_line(root, "built in", status))
            .collect()
    };
    let enrolled_line = |root: &Logged| anchor_line(root, "enrolled", Status::Trusted);
    let roots_revoked = facts.roots.len();
    let mut signed = built_in(Status::Trusted);
    signed.extend([
        applied_signed_line(&facts.signing_root, 1, 0),
        enrolled_line(facts.e_root),
        summary_line(
            facts.roots.len().saturating_add(1),
            1,
            facts.revoked_before,
            facts.floor,
        ),
        BUNDLE_VERIFIED.to_owned(),
    ]);
    let mut unanswered = built_in(Status::Trusted);
    unanswered.extend([
        "boot: trust request: \\EFI\\seraph\\trust-request is unsigned".to_owned(),
        anchor_request_line(facts.f_root),
        CONFIRM_PROMPT.to_owned(),
        refused_line("no confirmation came within 60 seconds"),
        enrolled_line(facts.e_root),
        summary_line(
            facts.roots.len().saturating_add(1),
            1,
            facts.revoked_before,
            facts.floor,
        ),
        BUNDLE_VERIFIED.to_owned(),
    ]);
    let mut answered = built_in(Status::Trusted);
    answered.extend([
        "boot: trust request: applied, confirmed at the console: 1 anchors added, 0 removed, \
         0 key ids revoked"
            .to_owned(),
        enrolled_line(facts.e_root),
        enrolled_line(facts.f_root),
        summary_line(
            facts.roots.len().saturating_add(2),
            2,
            facts.revoked_before,
            facts.floor,
        ),
        BUNDLE_VERIFIED.to_owned(),
    ]);
    let mut commit_refused = built_in(Status::Trusted);
    commit_refused.extend([
        refused_line(
            "the boot set does not verify under the trust store it would give: signature \
             verification refused: kernel: Failed(Revoked)",
        ),
        summary_line(
            facts.roots.len().saturating_add(2),
            2,
            facts.revoked_before,
            facts.floor,
        ),
        BUNDLE_VERIFIED.to_owned(),
    ]);
    let mut revoked = built_in(Status::Revoked);
    revoked.extend([
        applied_signed_line(&facts.e_root.id, 0, roots_revoked),
        enrolled_line(facts.e_root),
        enrolled_line(facts.f_root),
        summary_line(
            facts.roots.len().saturating_add(2),
            2,
            facts.revoked_before.saturating_add(roots_revoked),
            facts.floor,
        ),
        BUNDLE_VERIFIED.to_owned(),
    ]);
    let mut holds = built_in(Status::Revoked);
    holds.extend([
        "boot: trust request: changes nothing (already applied); skipped".to_owned(),
        summary_line(
            facts.roots.len().saturating_add(2),
            2,
            facts.revoked_before.saturating_add(roots_revoked),
            facts.floor,
        ),
        format!("{BOOT_FATAL}signature verification refused: kernel: Failed(Revoked)"),
    ]);

    [signed, unanswered, answered, commit_refused, revoked, holds]
}

/// `id` as lowercase hex, as the bootloader logs a key id.
fn hex(id: &KeyId) -> String
{
    use std::fmt::Write as _;
    id.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// The bootloader's line of `anchor` of the store it runs on, from `source`
/// (`core/boot/src/enrolment.rs`).
fn anchor_line(anchor: &Logged, source: &str, status: Status) -> String
{
    format!(
        "boot: trust anchor \"{}\" key id {}: {source}{}{}",
        anchor.label,
        hex(&anchor.id),
        if anchor.local
        {
            ", locally generated"
        }
        else
        {
            ""
        },
        match status
        {
            Status::Trusted => "",
            Status::Revoked => ", revoked",
        },
    )
}

/// The bootloader's line of an anchor an unconfirmed request adds, up to its
/// roles.
fn anchor_request_line(anchor: &Logged) -> String
{
    format!(
        "boot: trust request: add root \"{}\" key id {}, roles ",
        anchor.label,
        hex(&anchor.id)
    )
}

/// The bootloader's line of the store it runs on.
fn summary_line(anchors: usize, enrolled: usize, revoked: usize, floor: u32) -> String
{
    format!(
        "boot: trust store: {anchors} anchors ({enrolled} enrolled), {revoked} revoked key ids, \
         security floor {floor}"
    )
}

/// The bootloader's line once it applied a request signed for enrolment
/// under the anchor `by`.
fn applied_signed_line(by: &KeyId, added: usize, revoked: usize) -> String
{
    format!(
        "boot: trust request: applied, signed for enrolment by key id {}: {added} anchors \
         added, 0 removed, {revoked} key ids revoked",
        hex(by)
    )
}

/// The bootloader's line refusing a request, `why`.
fn refused_line(why: &str) -> String
{
    format!("boot: trust request: refused: {why}; this boot runs on the current trust store")
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: an owed line that differs from the bootloader's, so a
    // boot that did what it should fails at its deadline.
    #[test]
    fn the_owed_lines_are_the_bootloaders()
    {
        let anchor = Logged {
            label: "local build root".to_owned(),
            id: [0xab; objsig::KEY_ID_LEN],
            local: true,
        };
        assert_eq!(
            anchor_line(&anchor, "built in", Status::Revoked),
            "boot: trust anchor \"local build root\" key id abababababababababababababababab: \
             built in, locally generated, revoked"
        );
        assert_eq!(
            summary_line(3, 2, 1, 1),
            "boot: trust store: 3 anchors (2 enrolled), 1 revoked key ids, security floor 1"
        );
        assert_eq!(
            applied_signed_line(&[1; objsig::KEY_ID_LEN], 1, 0),
            "boot: trust request: applied, signed for enrolment by key id \
             01010101010101010101010101010101: 1 anchors added, 0 removed, 0 key ids revoked"
        );
        assert_eq!(
            refused_line("why"),
            "boot: trust request: refused: why; this boot runs on the current trust store"
        );
    }
}
