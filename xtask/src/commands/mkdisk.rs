// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! commands/mkdisk.rs
//!
//! Mkdisk command: re-mirror `rootfs/` into `sysroot/`, re-synthesise
//! test fixtures, and regenerate `disk.img` without invoking cargo.
//! Used to refresh the boot image after `rootfs/` or sysroot files
//! were edited outside the cargo flow (notably: staging a test recipe
//! by copying it from `sysroot/config/svcmgr/tests/` into
//! `sysroot/config/svcmgr/services/`).
//!
//! `--repack-only` skips the `rootfs/` re-mirror and packs the sysroot as it
//! stands. The mirror is additive (it copies rootfs files over the sysroot but
//! never deletes), so a default recipe removed from the staged sysroot would be
//! restored by a normal repack; `--repack-only` lets a test boot compose an
//! exact service set by removing such a recipe and packing without the restore.

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
    disk::create_disk_image(ctx, args.arch)?;
    step(&format!("mkdisk complete ({})", args.arch));
    Ok(())
}
