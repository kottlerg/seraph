// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! commands/compose_bundle.rs
//!
//! Compose the bootloader bundle from `sysroot/services/` binaries and
//! repack the disk image. Symmetric with `mkdisk`: both call
//! `disk::create_disk_image` after editing the sysroot, the difference
//! being which file in the ESP staging area they author. This command
//! authors `bootstrap.bundle`; `mkdisk` never does.

use anyhow::Result;

use crate::bundle;
use crate::cli::ComposeBundleArgs;
use crate::context::Context as BuildContext;
use crate::disk;
use crate::sysroot;
use crate::util::step;

/// Entry point for `cargo xtask compose-bundle`. Composes the chosen
/// harness bundle (overwriting any existing one) and repacks `disk.img`.
/// Requires a populated sysroot — run `cargo xtask build` first.
pub fn run(ctx: &BuildContext, args: &ComposeBundleArgs) -> Result<()>
{
    sysroot::check_arch(ctx, args.arch)?;
    bundle::compose(ctx, args.harness)?;
    disk::create_disk_image(ctx, args.arch)?;
    step(&format!(
        "compose-bundle complete (harness={:?}, {})",
        args.harness, args.arch
    ));
    Ok(())
}
