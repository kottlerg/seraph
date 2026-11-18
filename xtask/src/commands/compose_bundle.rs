// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/compose_bundle.rs

//! Compose the bootloader bundle from the sysroot's installed files and
//! repack the disk image. Symmetric with `mkdisk`: both call
//! `disk::create_disk_image` after editing the sysroot, the difference
//! being which file in the ESP staging area they author. This command
//! authors `bootstrap.bundle`; `mkdisk` never does.

use crate::error::Result;

use crate::bundle;
use crate::cli::ComposeBundleArgs;
use crate::context::Context as BuildContext;
use crate::disk;
use crate::signing;
use crate::sysroot;
use crate::util::step;

/// Entry point for `cargo xtask compose-bundle`. Installs the bundle's data
/// entries from the repository, signs the sysroot for the chosen harness,
/// composes its bundle (overwriting any existing one) and repacks
/// `disk.img`. Requires a populated sysroot — run `cargo xtask build`
/// first.
pub fn run(ctx: &BuildContext, args: &ComposeBundleArgs) -> Result<()>
{
    sysroot::check_arch(ctx, args.arch)?;
    sysroot::install_data_entries(ctx, args.arch)?;
    signing::sign_for_harness(ctx, args.arch, args.harness)?;
    bundle::compose(ctx, args.arch, args.harness)?;
    disk::create_disk_image(ctx, args.arch, disk::DiskLayout::default())?;
    step(&format!(
        "compose-bundle complete (harness={:?}, {})",
        args.harness, args.arch
    ));
    Ok(())
}
