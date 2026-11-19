// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/compose_bundle.rs

//! Choose the harness whose bundle the disk image boots, and repack it. The
//! harness is recorded in the sysroot (`crate::sysroot::record_harness`), and
//! every later pack, `mkdisk`'s included, composes that harness's bundle
//! from the installed files its bundle list names, until a full build or
//! another `compose-bundle` records another.

use crate::argparse::ValueEnum as _;
use crate::error::Result;

use crate::cli::ComposeBundleArgs;
use crate::context::Context as BuildContext;
use crate::disk;
use crate::sysroot;
use crate::util::step;

/// Entry point for `cargo xtask compose-bundle`. Installs the repository's
/// data files, records the chosen harness, and repacks `disk.img`, which
/// signs the sysroot for that harness and composes the ESP, its bundle
/// included, from the installed files. Requires a populated sysroot: run
/// `cargo xtask build` first.
pub fn run(ctx: &BuildContext, args: &ComposeBundleArgs) -> Result<()>
{
    sysroot::check_arch(ctx, args.arch)?;
    sysroot::install_data_files(ctx, args.arch)?;
    sysroot::record_harness(ctx, args.harness)?;
    disk::create_disk_image(ctx, args.arch, disk::DiskLayout::default())?;
    step(&format!(
        "compose-bundle complete (harness={}, {})",
        args.harness.name(),
        args.arch
    ));
    Ok(())
}
