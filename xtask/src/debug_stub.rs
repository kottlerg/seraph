// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/debug_stub.rs

//! Staging the GDB stub for one boot, and the GDB command line that
//! connects to it.
//!
//! The stub's recipe template lives at `config/svcmgr/debug/gdbstub.svc`,
//! which svcmgr does not scan. Staging writes it into
//! `config/svcmgr/services/` with the target's name appended to its `argv`
//! and repacks the disk images in the layout they already had (the block
//! size of `disk.img`, and the data partition on `disk-data.img` when one
//! is there), so a 4Kn or split boot stays one; unstaging removes it and
//! repacks again in that layout.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

use crate::arch::Arch;
use crate::context::Context;
use crate::disk::DiskLayout;

/// The stub's recipe file name, in the template directory and once staged.
const RECIPE: &str = "gdbstub.svc";

/// The longest target name: procmgr records a process's name truncated to
/// `svcmgr_labels::NAME_MAX` (64) bytes, so a longer one never matches.
const NAME_MAX: usize = 64;

/// Where the stub's recipe template is installed in the sysroot.
fn template(ctx: &Context) -> PathBuf
{
    ctx.sysroot.join("config/svcmgr/debug").join(RECIPE)
}

/// Where the staged recipe goes.
fn staged(ctx: &Context) -> PathBuf
{
    ctx.sysroot.join("config/svcmgr/services").join(RECIPE)
}

/// The template's recipe with `target` appended to its `argv` line.
fn recipe_for(template: &str, target: &str) -> Result<String>
{
    if target.is_empty() || target.contains(char::is_whitespace)
    {
        bail!("debug target name {target:?} must be one word");
    }
    if target.len() > NAME_MAX
    {
        bail!("debug target name {target:?} is longer than procmgr's {NAME_MAX}-byte names");
    }
    let mut found = false;
    let lines: Vec<String> = template
        .lines()
        .map(|line| {
            if line.starts_with("argv") && line.contains('=')
            {
                found = true;
                format!("{line} {target}")
            }
            else
            {
                line.to_string()
            }
        })
        .collect();
    if !found
    {
        bail!("the gdbstub recipe template has no argv line");
    }
    Ok(lines.join("\n") + "\n")
}

/// Stage the stub for `target` and repack the disk images in the layout
/// they have; returns that layout, for [`unstage`]. A failed repack removes
/// the staged recipe again and leaves the images to a rebuild.
pub fn stage(ctx: &Context, arch: Arch, target: &str) -> Result<DiskLayout>
{
    let layout = crate::disk::current_layout(ctx)?;
    let template_path = template(ctx);
    let text = std::fs::read_to_string(&template_path)
        .with_context(|| format!("reading {}", template_path.display()))?;
    let recipe = recipe_for(&text, target)?;
    let dst = staged(ctx);
    std::fs::write(&dst, recipe).with_context(|| format!("writing {}", dst.display()))?;
    if let Err(e) = crate::disk::create_disk_image(ctx, arch, layout)
    {
        // The recipe goes again, so a later repack does not pick it up.
        let _ = std::fs::remove_file(&dst);
        return Err(e.context("repacking the disk images with the gdbstub staged"));
    }
    Ok(layout)
}

/// Remove the staged stub and repack the disk images in `layout`, the one
/// [`stage`] returned.
pub fn unstage(ctx: &Context, arch: Arch, layout: DiskLayout) -> Result<()>
{
    let dst = staged(ctx);
    match std::fs::remove_file(&dst)
    {
        Ok(()) =>
        {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound =>
        {}
        Err(e) => return Err(e).with_context(|| format!("removing {}", dst.display())),
    }
    crate::disk::create_disk_image(ctx, arch, layout)
        .context("repacking the disk images without the gdbstub")
}

/// The sysroot binary a process named `target` runs, best effort: a staged
/// recipe whose `argv` begins with the name gives its `binary`; otherwise
/// `/programs/<target>` or `/services/<target>` when one exists.
pub fn binary_for(ctx: &Context, target: &str) -> Option<PathBuf>
{
    let dir = ctx.sysroot.join("config/svcmgr/services");
    if let Ok(entries) = std::fs::read_dir(&dir)
    {
        for entry in entries.flatten()
        {
            let Ok(text) = std::fs::read_to_string(entry.path())
            else
            {
                continue;
            };
            if let Some(binary) = recipe_binary_named(&text, target)
            {
                return Some(ctx.sysroot.join(binary.trim_start_matches('/')));
            }
        }
    }
    ["programs", "services"]
        .iter()
        .map(|d| ctx.sysroot.join(d).join(target))
        .find(|p| p.is_file())
}

/// The `binary` of `recipe` when its `argv` begins with `name`.
fn recipe_binary_named<'a>(recipe: &'a str, name: &str) -> Option<&'a str>
{
    let value = |key: &str| {
        recipe.lines().find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == key).then(|| v.trim())
        })
    };
    let argv0 = value("argv")?.split_whitespace().next()?;
    (argv0 == name).then(|| value("binary")).flatten()
}

/// The GDB architecture name of `arch`.
pub fn gdb_architecture(arch: Arch) -> &'static str
{
    match arch
    {
        Arch::X86_64 => "i386:x86-64",
        Arch::Riscv64 => "riscv:rv64",
    }
}

/// The GDB command line that connects to the stub on `port` with `binary`'s
/// symbols; the stub reports the load offset (`qOffsets`), so GDB relocates
/// them itself.
pub fn gdb_command(arch: Arch, port: u16, binary: Option<&Path>) -> String
{
    let file = binary.map_or_else(|| "<binary>".to_string(), |b| b.display().to_string());
    format!(
        "gdb -ex 'set architecture {}' -ex 'set remotetimeout 30' -ex 'target remote \
         localhost:{port}' {file}",
        gdb_architecture(arch)
    )
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn staging_appends_the_target_to_the_argv_line_alone()
    {
        let template = "# stub\nbinary = /services/gdbstub\nargv   = gdbstub\nseed = x\n";
        let recipe = recipe_for(template, "gdb-target").unwrap();
        assert!(recipe.contains("argv   = gdbstub gdb-target\n"));
        assert!(recipe.contains("binary = /services/gdbstub\n"));
        recipe_for(template, "two words").unwrap_err();
        recipe_for("binary = /x\n", "t").unwrap_err();
        // A name procmgr would truncate can never match.
        recipe_for(template, &"n".repeat(NAME_MAX)).unwrap();
        recipe_for(template, &"n".repeat(NAME_MAX + 1)).unwrap_err();
    }

    #[test]
    fn a_recipe_names_its_binary_by_its_first_argv_word()
    {
        let recipe = "binary = /programs/debugger\nargv = gdb-target --gdb-target\n";
        assert_eq!(
            recipe_binary_named(recipe, "gdb-target"),
            Some("/programs/debugger")
        );
        assert_eq!(recipe_binary_named(recipe, "debugger"), None);
    }
}
