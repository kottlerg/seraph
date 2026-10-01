// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/clean.rs

//! Clean command: remove the sysroot and optionally the cargo target/ directory.

use std::process::Command;

use anyhow::Result;

use crate::cli::CleanArgs;
use crate::context::Context as BuildContext;
use crate::util::{run_cmd, step};

/// Entry point for `cargo xtask clean`.
pub fn run(ctx: &BuildContext, args: &CleanArgs) -> Result<()>
{
    if ctx.sysroot.exists()
    {
        step(&format!("Removing sysroot: {}", ctx.sysroot.display()));
        std::fs::remove_dir_all(&ctx.sysroot)
            .map_err(|e| anyhow::anyhow!("failed to remove {}: {}", ctx.sysroot.display(), e))?;
    }
    else
    {
        step("Sysroot already clean");
    }

    let disk_img = ctx.disk_image();
    if disk_img.exists()
    {
        step(&format!("Removing disk image: {}", disk_img.display()));
        std::fs::remove_file(&disk_img)
            .map_err(|e| anyhow::anyhow!("failed to remove {}: {}", disk_img.display(), e))?;
    }

    if args.all
    {
        step("Removing cargo target/ directory");
        run_cmd(Command::new("cargo").args(["clean"]).current_dir(&ctx.root))?;
    }

    step("Clean complete");
    Ok(())
}
