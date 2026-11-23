// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/clean.rs

//! Clean command: remove the sysroot, the symbols store, the disk images and
//! any per-launch variable store a killed launch left, and optionally the
//! cargo target/ directory, whole or but for the standard library's build
//! units.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::error::{Context as _, Result};

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

    if args.keep_std
    {
        let lock =
            crate::rust_src::probe_real_sysroot()?.join("lib/rustlib/src/rust/library/Cargo.lock");
        let text =
            fs::read_to_string(&lock).with_context(|| format!("reading {}", lock.display()))?;
        step("Removing cargo target/ but the standard library's build units");
        prune_to_std(&ctx.target_dir, &library_packages(&text))?;
    }
    else if args.all
    {
        step("Removing cargo target/ directory");
        run_cmd(Command::new("cargo").args(["clean"]).current_dir(&ctx.root))?;
    }

    step("Clean complete");
    Ok(())
}

/// Cargo's profile directories, in `target/` for the host and in
/// `target/<triple>/` for each target.
const PROFILES: [&str; 2] = ["debug", "release"];

/// The packages the toolchain's `library/Cargo.lock` names: those a
/// `-Z build-std` build compiles from the toolchain's sources.
fn library_packages(lock: &str) -> BTreeSet<String>
{
    lock.lines()
        .filter_map(|line| line.strip_prefix("name = \""))
        .filter_map(|rest| rest.strip_suffix('"'))
        .map(str::to_owned)
        .collect()
}

/// Remove `path`, a directory with what it holds or a file.
fn remove(path: &Path) -> Result<()>
{
    let result = if path.is_dir() && !path.is_symlink()
    {
        fs::remove_dir_all(path)
    }
    else
    {
        fs::remove_file(path)
    };
    result.with_context(|| format!("removing {}", path.display()))
}

/// Empty Cargo's profile directories in `target`, the host's
/// (`target/<profile>/`) and each target's (`target/<triple>/<profile>/`), but
/// for the build units of `keep`'s packages: only `build/<package>/` of a
/// kept package stays. The rest of `target`, xtask's own state among it
/// (`target/xtask/`: the trust store, the logs, the review records), is left
/// alone. Cargo checks each unit it finds kept as it checks every unit, so a
/// kept unit whose inputs changed is rebuilt.
fn prune_to_std(target: &Path, keep: &BTreeSet<String>) -> Result<()>
{
    let prune_profile = |profile: &Path| -> Result<()> {
        for entry in
            fs::read_dir(profile).with_context(|| format!("reading {}", profile.display()))?
        {
            let path = entry.context("reading a directory entry")?.path();
            if path.file_name().is_some_and(|name| name == "build") && path.is_dir()
            {
                for unit in
                    fs::read_dir(&path).with_context(|| format!("reading {}", path.display()))?
                {
                    let unit = unit.context("reading a directory entry")?;
                    if !keep.contains(unit.file_name().to_string_lossy().as_ref())
                    {
                        remove(&unit.path())?;
                    }
                }
            }
            else
            {
                remove(&path)?;
            }
        }
        Ok(())
    };
    if !target.exists()
    {
        return Ok(());
    }
    for entry in fs::read_dir(target).with_context(|| format!("reading {}", target.display()))?
    {
        let path = entry.context("reading a directory entry")?.path();
        let name = path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        if PROFILES.contains(&name.as_str()) && path.is_dir()
        {
            prune_profile(&path)?;
        }
        else if !path.is_symlink() && PROFILES.iter().any(|p| path.join(p).join("build").is_dir())
        {
            // A target's directory: its profile directories.
            for profile in PROFILES
            {
                let sub = path.join(profile);
                if sub.is_dir() && !sub.is_symlink()
                {
                    prune_profile(&sub)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: a library package missed, so CI's cache drops its unit,
    // or a line that is no package name taken for one.
    #[test]
    fn the_library_packages_are_the_lock_names()
    {
        let lock = "version = 4\n\n[[package]]\nname = \"core\"\nversion = \"0.0.0\"\n\n\
                    [[package]]\nname = \"rustc-std-workspace-core\"\nsource = \"x\"\n";
        let names: Vec<String> = library_packages(lock).into_iter().collect();
        assert_eq!(names, ["core", "rustc-std-workspace-core"]);
    }

    // Defect caught: a workspace unit kept in the cache, where its fixed
    // modification times could pass a changed source as fresh, a library
    // unit dropped from it, or xtask's own state in target/ (the trust
    // store, logs, review records) removed with the build output.
    #[test]
    fn only_the_library_units_stay()
    {
        let target = std::env::temp_dir().join(format!("xtask-keep-std-{}", std::process::id()));
        let _ = fs::remove_dir_all(&target);
        for dir in [
            "debug/build/compiler_builtins/1/out",
            "debug/build/xtask/2/out",
            "debug/incremental/x",
            "x86_64-seraph-none/debug/build/core/3/out",
            "x86_64-seraph-none/debug/build/kernel/4/out",
            "x86_64-seraph-none/release/build/alloc/5",
            "seraph-toolchain/lib",
            "xtask/test",
        ]
        {
            fs::create_dir_all(target.join(dir)).unwrap();
        }
        for file in [
            "CACHEDIR.TAG",
            "debug/xtask",
            "x86_64-seraph-none/debug/kernel",
            "xtask/signing.toml",
        ]
        {
            fs::write(target.join(file), b"x").unwrap();
        }
        let keep: BTreeSet<String> = ["core", "alloc", "compiler_builtins"]
            .map(str::to_owned)
            .into();
        prune_to_std(&target, &keep).unwrap();
        let mut left = Vec::new();
        let mut stack = vec![target.clone()];
        while let Some(dir) = stack.pop()
        {
            for entry in fs::read_dir(&dir).unwrap()
            {
                let path = entry.unwrap().path();
                if path.is_dir() && fs::read_dir(&path).unwrap().next().is_some()
                {
                    stack.push(path);
                }
                else
                {
                    left.push(path.strip_prefix(&target).unwrap().display().to_string());
                }
            }
        }
        left.sort();
        assert_eq!(
            left,
            [
                "CACHEDIR.TAG",
                "debug/build/compiler_builtins/1/out",
                "seraph-toolchain/lib",
                "x86_64-seraph-none/debug/build/core/3/out",
                "x86_64-seraph-none/release/build/alloc/5",
                "xtask/signing.toml",
                "xtask/test"
            ]
        );
        fs::remove_dir_all(&target).unwrap();
    }
}
