// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/clean.rs

//! Clean command: remove the sysroot, the symbols store, the disk images and
//! any per-launch variable store a killed launch left, and optionally the
//! cargo target/ directory.

use std::process::Command;

use crate::error::Result;

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
            .map_err(|e| crate::error::err!("failed to remove {}: {}", ctx.sysroot.display(), e))?;
    }
    else
    {
        step("Sysroot already clean");
    }

    let symbols = ctx.symbols_dir();
    if symbols.exists()
    {
        step(&format!("Removing symbols store: {}", symbols.display()));
        std::fs::remove_dir_all(&symbols)
            .map_err(|e| crate::error::err!("failed to remove {}: {}", symbols.display(), e))?;
    }

    for disk_img in [ctx.disk_image(), ctx.data_disk_image()]
    {
        if disk_img.exists()
        {
            step(&format!("Removing disk image: {}", disk_img.display()));
            std::fs::remove_file(&disk_img).map_err(|e| {
                crate::error::err!("failed to remove {}: {}", disk_img.display(), e)
            })?;
        }
    }

    let vars = crate::qemu::launch_vars_dir(ctx);
    if vars.exists()
    {
        step(&format!(
            "Removing per-launch variable stores: {}",
            vars.display()
        ));
        std::fs::remove_dir_all(&vars)
            .map_err(|e| crate::error::err!("failed to remove {}: {}", vars.display(), e))?;
    }

    if args.all
    {
        step("Removing cargo target/ directory");
        run_cmd(Command::new("cargo").args(["clean"]).current_dir(&ctx.root))?;
    }

    step("Clean complete");
    Ok(())
}
