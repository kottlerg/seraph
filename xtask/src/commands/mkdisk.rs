// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/mkdisk.rs

//! Mkdisk command: re-mirror `rootfs/` into `sysroot/`, re-synthesise test
//! fixtures, choose what the image boots (the harness whose bundle it
//! composes, the bootloader's knobs, the log-level configuration), and
//! regenerate `disk.img` (and `disk-data.img` under `--split-data`) at the
//! requested block size without invoking cargo. The pack checks the images it
//! writes ([`crate::image_check`]). Hand-staging a test recipe (copying it
//! from `sysroot/config/svcmgr/tests/` into `sysroot/config/svcmgr/services/`)
//! requires `--repack-only`, since a normal re-mirror is authoritative and
//! would prune the hand-added file.
//!
//! `--repack-only` skips the `rootfs/` re-mirror and packs the sysroot as it
//! stands, except that the repository's data files (the log-level
//! configuration, or the file `--log-levels` names, and the platform tables)
//! are installed over their copies in either case. A normal re-mirror is
//! authoritative over the rootfs-managed subtrees (`config/`, `data/`): it
//! restores recipes that exist in `rootfs/` and removes sysroot ones that do
//! not. `--repack-only` lets a test boot compose a service
//! set that diverges from `rootfs/` — e.g. a default recipe removed, or a test
//! recipe hand-staged — by packing the staged sysroot without that pass.

use std::path::Path;

use crate::argparse::ValueEnum as _;
use crate::error::{Context as _, Result, bail};

use crate::cli::MkdiskArgs;
use crate::context::Context as BuildContext;
use crate::disk;
use crate::esp::{self, Knob};
use crate::sysroot::{self, LOG_LEVELS};
use crate::util::step;

/// Entry point for `cargo xtask mkdisk`. Re-mirrors `rootfs/` into the
/// sysroot (including the test-fixture synthesis) unless `--repack-only`,
/// installs the repository's data files in either case, then the log-level
/// configuration `--log-levels` names over the repository's, records the
/// harness `--harness` names, stages exactly the knobs `--knob` names, and
/// regenerates `disk.img` (and `disk-data.img` under `--split-data`) at the
/// requested block size. Cargo is not invoked; the existing per-arch sysroot
/// from a prior `cargo xtask build` is reused.
///
/// # Errors
///
/// When the sysroot was built for another architecture, the `--log-levels`
/// file cannot be read or holds a line init's parser refuses, and as
/// [`sysroot::install_rootfs`], [`esp::set_knobs`] and
/// [`disk::create_disk_image`] fail.
pub fn run(ctx: &BuildContext, args: &MkdiskArgs) -> Result<()>
{
    sysroot::check_arch(ctx, args.arch)?;
    // Read and checked before anything changes, so a refused file leaves the
    // sysroot as it was.
    let levels = args
        .log_levels
        .as_deref()
        .map(read_log_levels)
        .transpose()?;
    if args.repack_only
    {
        sysroot::install_data_files(ctx, args.arch)?;
    }
    else
    {
        sysroot::install_rootfs(ctx, args.arch)?;
    }
    if let Some(levels) = &levels
    {
        let installed = ctx.sysroot.join(LOG_LEVELS.relative());
        std::fs::write(&installed, levels)
            .with_context(|| format!("writing {}", installed.display()))?;
    }
    if let Some(harness) = args.harness
    {
        sysroot::record_harness(ctx, harness)?;
    }
    esp::set_knobs(ctx, &args.knob)?;
    let layout = disk::DiskLayout {
        block_size: args.block_size,
        data: if args.split_data
        {
            disk::DataPlacement::SecondImage
        }
        else
        {
            disk::DataPlacement::MainImage
        },
    };
    disk::create_disk_image(ctx, args.arch, layout)?;
    step(&format!(
        "mkdisk complete ({}, harness={}, knobs={})",
        args.arch,
        sysroot::recorded_harness(ctx)?.name(),
        knob_names(&args.knob)
    ));
    Ok(())
}

/// The log-level configuration at `path`, refused unless init's parser
/// accepts every line of it: init would report and ignore a refused line, so
/// the boot would run at levels the file does not state.
///
/// # Errors
///
/// When the file cannot be read, or init's parser refuses a line, naming the
/// line and why.
fn read_log_levels(path: &Path) -> Result<Vec<u8>>
{
    let text = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    check_log_levels(&text).with_context(|| format!("checking {}", path.display()))?;
    Ok(text)
}

/// Refuse `text` unless init's log-level parser accepts each of its lines.
///
/// # Errors
///
/// On the first line the parser refuses, naming it and why.
fn check_log_levels(text: &[u8]) -> Result<()>
{
    let mut refused = None;
    let _levels = init_log_levels::parse(text, |line, error| {
        refused.get_or_insert_with(|| {
            format!("{:?}: {}", String::from_utf8_lossy(line), error.describe())
        });
    });
    match refused
    {
        Some(line) => bail!("init's log-level parser refuses the line {line}"),
        None => Ok(()),
    }
}

/// `knobs` by name, comma-separated, or `none`.
fn knob_names(knobs: &[Knob]) -> String
{
    if knobs.is_empty()
    {
        return "none".to_owned();
    }
    knobs
        .iter()
        .map(|knob| knob.name())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: a configuration with a mistyped service or level packed,
    // so init ignores that line and the boot runs at levels the file does not
    // state.
    #[test]
    fn a_configuration_with_a_line_init_refuses_is_refused()
    {
        check_log_levels(b"# vfsd at debug\nvfsd = debug\n\nprocmgr = info\n").unwrap();
        for bad in [
            b"vfs = debug\n".as_slice(),
            b"vfsd = loud\n",
            b"vfsd debug\n",
        ]
        {
            let error = format!("{:#}", check_log_levels(bad).unwrap_err());
            assert!(error.contains("refuses the line"), "{error}");
        }
    }
}
