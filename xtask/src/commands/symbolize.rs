// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/symbolize.rs

//! `cargo xtask symbolize` — resolve runtime addresses in a loaded ELF image
//! to function, file, and line.
//!
//! The image is a binary named by path, or the sysroot's kernel. Each address
//! less the load bias is an address in the image's link-time address space;
//! the resolution itself is [`crate::symbolize`]'s. With `--log`, the
//! addresses are those of every crash-report block in a serial log, each
//! against its process's sysroot binary ([`crate::crash_log`]).

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

use crate::cli::SymbolizeArgs;
use crate::context::Context;
use crate::crash_log::{SysrootImages, symbolize_log};
use crate::symbolize::{Symbolizer, format_resolution, image_address};

/// Entry point for `cargo xtask symbolize`.
///
/// # Errors
///
/// Fails when the image or the log cannot be read, when the image cannot be
/// parsed, or when an address lies below the load bias.
pub fn run(ctx: &Context, args: &SymbolizeArgs) -> Result<()>
{
    if let Some(log) = &args.log
    {
        return run_log(ctx, log);
    }
    let binary = image_path(ctx, args);
    let data =
        std::fs::read(&binary).with_context(|| format!("cannot read {}", binary.display()))?;
    let symbolizer =
        Symbolizer::new(&data).with_context(|| format!("cannot symbolize {}", binary.display()))?;
    if !symbolizer.has_debug_info()
    {
        println!(
            "{}: no debug information; resolving from the symbol table",
            binary.display()
        );
    }
    for &addr in &args.addresses
    {
        let vaddr = image_address(addr, args.bias)?;
        let resolution = symbolizer
            .resolve(vaddr)
            .with_context(|| format!("cannot resolve {addr:#x}"))?;
        for line in format_resolution(addr, vaddr, &resolution)
        {
            println!("{line}");
        }
    }
    Ok(())
}

/// The log form: every crash-report block of `log`, symbolized against the
/// sysroot.
fn run_log(ctx: &Context, log: &Path) -> Result<()>
{
    let bytes = std::fs::read(log).with_context(|| format!("cannot read {}", log.display()))?;
    let images = SysrootImages {
        sysroot: ctx.sysroot.clone(),
    };
    match symbolize_log(&String::from_utf8_lossy(&bytes), &images)
    {
        Some(report) => print!("{report}"),
        None => println!("{}: no crash-report block", log.display()),
    }
    Ok(())
}

/// The image the addresses fall in: `--binary`, else the sysroot's kernel.
fn image_path(ctx: &Context, args: &SymbolizeArgs) -> PathBuf
{
    match &args.binary
    {
        Some(path) => path.clone(),
        None => ctx.sysroot_efi_seraph().join("kernel"),
    }
}
