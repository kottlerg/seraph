// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! commands/disk.rs
//!
//! Disk command: repack `sysroot/` and regenerate `disk.img` without
//! invoking cargo. Used to refresh the boot image after `rootfs/` or
//! sysroot files were edited outside the cargo flow (notably: staging
//! a test recipe by copying it from `sysroot/etc/svcmgr/tests.d/` into
//! `sysroot/etc/svcmgr/services.d/`).

use anyhow::Result;

use crate::cli::DiskArgs;
use crate::context::Context as BuildContext;
use crate::disk;
use crate::sysroot;
use crate::util::step;

/// Entry point for `cargo xtask disk`. Re-mirrors `rootfs/` into the
/// sysroot (including the test-fixture synthesis), then regenerates
/// `disk.img`. Cargo is not invoked; the existing per-arch sysroot
/// from a prior `cargo xtask build` is reused.
pub fn run(ctx: &BuildContext, args: &DiskArgs) -> Result<()>
{
    sysroot::check_arch(ctx, args.arch)?;
    sysroot::install_rootfs(ctx)?;
    disk::create_disk_image(ctx)?;
    step(&format!("Disk repack complete ({})", args.arch));
    Ok(())
}
