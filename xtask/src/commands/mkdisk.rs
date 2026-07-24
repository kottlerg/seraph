// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! commands/mkdisk.rs
//!
//! Mkdisk command: re-mirror `rootfs/` into `sysroot/`, re-synthesise
//! test fixtures, and regenerate `disk.img` without invoking cargo.
//! Used to refresh the boot image after `rootfs/` or sysroot files were
//! edited outside the cargo flow. Hand-staging a test recipe (copying it
//! from `sysroot/config/svcmgr/tests/` into `sysroot/config/svcmgr/services/`)
//! requires `--repack-only`, since a normal re-mirror is authoritative and
//! would prune the hand-added file.
//!
//! `--repack-only` skips the `rootfs/` re-mirror and packs the sysroot as it
//! stands. A normal re-mirror is authoritative over the rootfs-managed subtrees
//! (`config/`, `data/`): it restores recipes that exist in `rootfs/` and removes
//! sysroot ones that do not. `--repack-only` lets a test boot compose a service
//! set that diverges from `rootfs/` — e.g. a default recipe removed, or a test
//! recipe hand-staged — by packing the staged sysroot without that pass.

use anyhow::Result;

use crate::cli::MkdiskArgs;
use crate::context::Context as BuildContext;
use crate::disk;
use crate::sysroot;
use crate::util::step;

/// Entry point for `cargo xtask mkdisk`. Re-mirrors `rootfs/` into the
/// sysroot (including the test-fixture synthesis), then regenerates
/// `disk.img`. Cargo is not invoked; the existing per-arch sysroot
/// from a prior `cargo xtask build` is reused.
pub fn run(ctx: &BuildContext, args: &MkdiskArgs) -> Result<()>
{
    sysroot::check_arch(ctx, args.arch)?;
    if !args.repack_only
    {
        sysroot::install_rootfs(ctx)?;
    }
    stage_nokaslr_knob(ctx, args.no_kaslr)?;
    disk::create_disk_image(ctx, args.arch)?;
    step(&format!("mkdisk complete ({})", args.arch));
    Ok(())
}

/// Stage or remove the `\EFI\seraph\nokaslr` override knob in the ESP tree so
/// the next `disk.img` reflects the requested KASLR state. Idempotent: an
/// absent file re-enables randomization, a present (empty) file disables it.
pub fn stage_nokaslr_knob(ctx: &BuildContext, disable: bool) -> Result<()>
{
    let path = ctx.sysroot_efi_seraph().join("nokaslr");
    if disable
    {
        std::fs::create_dir_all(ctx.sysroot_efi_seraph())?;
        std::fs::write(&path, b"")?;
    }
    else if path.exists()
    {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}
