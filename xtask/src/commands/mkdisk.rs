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
    sysroot::install_rootfs(ctx)?;
    disk::create_disk_image(ctx, args.arch)?;
    step(&format!("mkdisk complete ({})", args.arch));
    Ok(())
}
