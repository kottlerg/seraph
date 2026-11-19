// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/symbolize.rs

//! `cargo xtask symbolize` — resolve runtime addresses in a loaded ELF image
//! to function, file, and line.
//!
//! The image is a binary named by path, or the sysroot's kernel; its symbols
//! are its own or, for a stripped image, the symbols store's file of its
//! build id ([`crate::symbolize::store`]). Each address less the load bias is
//! an address in the image's link-time address space; the resolution itself
//! is [`crate::symbolize`]'s. With `--log`, the addresses are those of every
//! crash-report block in a serial log, each against its process's sysroot
//! binary, or against the store's file of that binary when `--symbols` names
//! a store ([`crate::crash_log`]).

use std::path::{Path, PathBuf};

use crate::error::{Context as _, Result};

use crate::cli::SymbolizeArgs;
use crate::context::Context;
use crate::crash_log::{ImageSource, StoreImages, SysrootImages, symbolize_log};
use crate::symbolize::store::{Store, Symbols};
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
        return run_log(ctx, args, log);
    }
    let binary = image_path(ctx, args);
    let image =
        std::fs::read(&binary).with_context(|| format!("cannot read {}", binary.display()))?;
    let store_dir = args.symbols.clone().unwrap_or_else(|| ctx.symbols_dir());
    let data = match Store::at(&store_dir).symbols(&image)
    {
        Ok(Symbols::Image) => image,
        Ok(Symbols::Store { name, elf }) =>
        {
            println!(
                "{}: symbols from {} (by its build id)",
                binary.display(),
                store_dir.join(name).display()
            );
            elf
        }
        Err(reason) => crate::error::bail!("no symbols for {}: {reason}", binary.display()),
    };
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
/// sysroot and its symbols store, or against the store `--symbols` names
/// alone.
fn run_log(ctx: &Context, args: &SymbolizeArgs, log: &Path) -> Result<()>
{
    let bytes = std::fs::read(log).with_context(|| format!("cannot read {}", log.display()))?;
    let images: Box<dyn ImageSource> = match &args.symbols
    {
        Some(dir) => Box::new(StoreImages::open(dir.clone())?),
        None => Box::new(SysrootImages {
            sysroot: ctx.sysroot.clone(),
            symbols: ctx.symbols_dir(),
        }),
    };
    match symbolize_log(&String::from_utf8_lossy(&bytes), images.as_ref())
    {
        Some(report) => print!("{report}"),
        None => println!("{}: no crash-report block", log.display()),
    }
    Ok(())
}

/// The image the addresses fall in: `--binary`, or the sysroot's kernel for
/// `--kernel`. Without `--log`, which [`run`] takes first, the parser admits
/// exactly one of the two.
fn image_path(ctx: &Context, args: &SymbolizeArgs) -> PathBuf
{
    match (&args.binary, args.kernel)
    {
        (Some(path), false) => path.clone(),
        _ => ctx.sysroot_efi_seraph().join("kernel"),
    }
}
