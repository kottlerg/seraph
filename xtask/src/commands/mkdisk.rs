// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/mkdisk.rs

//! Mkdisk command: re-mirror `rootfs/` into `sysroot/`, re-synthesise
//! test fixtures, and regenerate `disk.img` (and `disk-data.img` under
//! `--split-data`) at the requested block size without invoking cargo.
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
/// `disk.img` (and `disk-data.img` under `--split-data`) at the requested
/// block size. Cargo is not invoked; the existing per-arch sysroot
/// from a prior `cargo xtask build` is reused.
pub fn run(ctx: &BuildContext, args: &MkdiskArgs) -> Result<()>
{
    sysroot::check_arch(ctx, args.arch)?;
    if !args.repack_only
    {
        sysroot::install_rootfs(ctx)?;
    }
    if args.no_kaslr
    {
        stage_knob(ctx, Knob::NoKaslr)?;
    }
    else
    {
        remove_knob(ctx, Knob::NoKaslr)?;
    }
    // The mapredo knob is `test-map-redo`'s alone, which removes it after its
    // boot; mkdisk's repack never keeps one a stopped run left behind.
    remove_knob(ctx, Knob::MapRedo)?;
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
    step(&format!("mkdisk complete ({})", args.arch));
    Ok(())
}

/// A presence-only bootloader knob: an empty file in the ESP tree's
/// `\EFI\seraph\` directory, read by the next boot of the `disk.img` packed
/// with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Knob
{
    /// `\EFI\seraph\nokaslr`: the bootloader boots the kernel at its
    /// deterministic (un-randomized) layout.
    NoKaslr,
    /// `\EFI\seraph\mapredo`: the bootloader redoes the first attempt of its
    /// steps 6 and 7 whatever its memory map's size.
    MapRedo,
}

impl Knob
{
    /// The knob's file name in `\EFI\seraph\`.
    fn file_name(self) -> &'static str
    {
        match self
        {
            Knob::NoKaslr => "nokaslr",
            Knob::MapRedo => "mapredo",
        }
    }
}

/// Stage `knob` in the ESP tree so the next `disk.img` carries it.
/// Idempotent.
pub fn stage_knob(ctx: &BuildContext, knob: Knob) -> Result<()>
{
    std::fs::create_dir_all(ctx.sysroot_efi_seraph())?;
    std::fs::write(ctx.sysroot_efi_seraph().join(knob.file_name()), b"")?;
    Ok(())
}

/// Remove `knob` from the ESP tree so the next `disk.img` lacks it.
/// Idempotent: an absent knob is left absent.
pub fn remove_knob(ctx: &BuildContext, knob: Knob) -> Result<()>
{
    let path = ctx.sysroot_efi_seraph().join(knob.file_name());
    if path.exists()
    {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}
