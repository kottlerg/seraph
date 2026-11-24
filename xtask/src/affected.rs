// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/affected.rs

//! What a change can affect: the files a change from a base commit touches,
//! and which of them are inputs of a workspace package's build. A command
//! that verifies only what a change can affect (`cargo xtask kani --since`)
//! selects from them.
//!
//! The inputs of a package's build are its own directory, the directories of
//! the workspace packages in its dependency closure, as `cargo metadata`
//! gives the path dependencies, the files those packages name in an
//! `include!`, `include_str!`, `include_bytes!` or `#[path]` string
//! literal, and the inputs of every build ([`WORKSPACE_WIDE`]). A package's
//! build script, features and `cfg` settings lie in its directory or the
//! workspace manifest. A caller adds the inputs of its own command.

use std::path::Path;
use std::process::Command;

use json::Value;

use crate::error::{Context, Result, bail, err};

/// The inputs of every package's build, each a file or, ending in `/`, a
/// directory: a change to one can change any package's build.
pub const WORKSPACE_WIDE: &[&str] = &[
    // The workspace manifest: its members, its workspace dependencies, and
    // the profiles, features and lints every package inherits.
    "Cargo.toml",
    // The version of every external crate a package builds with.
    "Cargo.lock",
    // The toolchain pin.
    "rust-toolchain.toml",
    // Cargo's configuration: flags and environment of every build.
    ".cargo/config.toml",
];

/// The `git grep -E` pattern of a line that names a file a crate reads from
/// its source: an `include!`, `include_str!` or `include_bytes!`, or a
/// `#[path]` module.
const READ_PATTERN: &str = r"include(_str|_bytes)?!|#\[path";

/// A workspace package, by its directory and the directories of the path
/// dependencies it declares, all relative to the workspace root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package
{
    pub name: String,
    pub dir: String,
    pub deps: Vec<String>,
}

/// A changed file that is an input of a package's build.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input
{
    /// The changed file, relative to the root.
    pub file: String,
    /// The package whose input it is: the one asked of, or a package in its
    /// dependency closure.
    pub package: String,
}

/// The workspace's packages and the files their sources read.
#[derive(Clone, Debug, Default)]
pub struct Workspace
{
    packages: Vec<Package>,
    /// Each source that names a file it reads, with that file, both relative
    /// to the root.
    reads: Vec<(String, String)>,
}

impl Workspace
{
    /// The workspace of the checkout at `root`, from `cargo metadata
    /// --no-deps` and the tracked Rust sources.
    pub fn load(root: &Path) -> Result<Self>
    {
        Ok(Self {
            packages: workspace_packages(root)?,
            reads: source_reads(root)?,
        })
    }

    /// The workspace of `packages`, whose sources read `reads`.
    #[cfg(test)]
    pub fn new(packages: Vec<Package>, reads: &[(&str, &str)]) -> Self
    {
        Self {
            packages,
            reads: reads
                .iter()
                .map(|(s, r)| ((*s).to_owned(), (*r).to_owned()))
                .collect(),
        }
    }

    /// The first file of `changed` (paths relative to the root) that is an
    /// input of the build of the package in `dir`, other than the inputs of
    /// every build, which the caller checks with [`first_under`]; `None` when
    /// none is. Fails when no workspace package lies in `dir`, whose closure
    /// cannot be known.
    pub fn first_input(&self, dir: &str, changed: &[String]) -> Result<Option<Input>>
    {
        let closure = closure(&self.packages, dir)
            .ok_or_else(|| err!("no workspace package lies in {dir}"))?;
        for package in closure
        {
            let read = self
                .reads
                .iter()
                .filter(|(source, _)| under(source, &package.dir))
                .map(|(_, read)| read.as_str());
            let inputs: Vec<&str> = core::iter::once(package.dir.as_str()).chain(read).collect();
            if let Some(file) = first_under(changed, &inputs)
            {
                return Ok(Some(Input {
                    file: file.clone(),
                    package: package.name.clone(),
                }));
            }
        }
        Ok(None)
    }
}

/// The first file of `changed` that is one of `inputs` or lies under one,
/// each a file or a directory, with or without its closing `/`.
pub fn first_under<'a>(changed: &'a [String], inputs: &[&str]) -> Option<&'a String>
{
    changed.iter().find(|f| inputs.iter().any(|i| under(f, i)))
}

/// Whether `file` is `input` or lies under it, `input` being a file or a
/// directory, with or without its closing `/`.
fn under(file: &str, input: &str) -> bool
{
    let dir = input.trim_end_matches('/');
    file == dir
        || file
            .strip_prefix(dir)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The package in `dir` and every workspace package its path dependencies
/// reach, of every kind (normal, development and build) and on every target,
/// which is what the host test build of it can compile; `None` when no
/// package lies in `dir`.
fn closure<'a>(packages: &'a [Package], dir: &str) -> Option<Vec<&'a Package>>
{
    let root = packages.iter().find(|p| p.dir == dir)?;
    let mut reached = vec![root];
    let mut next = 0;
    while let Some(package) = reached.get(next).copied()
    {
        next = next.saturating_add(1);
        for dep in &package.deps
        {
            if let Some(found) = packages.iter().find(|p| &p.dir == dep)
                && !reached.iter().any(|r| r.dir == found.dir)
            {
                reached.push(found);
            }
        }
    }
    Some(reached)
}

// ── What the repository gives ────────────────────────────────────────────────

/// The files the change from `base` to the working tree touches, relative to
/// the root: `git diff --name-only`, a rename as both its paths. Fails when
/// `base` names no commit of the checkout.
pub fn changed_files(root: &Path, base: &str) -> Result<Vec<String>>
{
    let verified = git(
        root,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{base}^{{commit}}"),
        ],
    )
    .with_context(|| {
        format!(
            "--since {base} names no commit of this checkout (a shallow clone lacks the \
                 base's history)"
        )
    })?;
    let commit = verified.trim();
    let diff = git(root, &["diff", "--name-only", "--no-renames", commit, "--"])?;
    Ok(diff
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect())
}

/// The workspace's packages, from `cargo metadata --no-deps`.
fn workspace_packages(root: &Path) -> Result<Vec<Package>>
{
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(root)
        .output()
        .context("failed to launch cargo metadata")?;
    if !output.status.success()
    {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let metadata = json::parse(&text).map_err(|e| err!("cargo metadata's output: {e}"))?;
    packages_of(&metadata)
}

/// The packages of `cargo metadata`'s output, their directories relative to
/// its `workspace_root`.
fn packages_of(metadata: &Value) -> Result<Vec<Package>>
{
    let root = metadata
        .get("workspace_root")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("cargo metadata names no workspace_root"))?;
    let Some(Value::Array(packages)) = metadata.get("packages")
    else
    {
        bail!("cargo metadata lists no packages");
    };
    let mut out = Vec::new();
    for package in packages
    {
        let name = package.get("name").and_then(Value::as_str);
        let manifest = package.get("manifest_path").and_then(Value::as_str);
        let (Some(name), Some(manifest)) = (name, manifest)
        else
        {
            bail!("cargo metadata gives a package without a name or a manifest path");
        };
        let dir = relative(
            root,
            manifest.strip_suffix("/Cargo.toml").unwrap_or(manifest),
        )
        .ok_or_else(|| err!("package {name} lies outside the workspace root"))?;
        let deps = match package.get("dependencies")
        {
            Some(Value::Array(deps)) => deps
                .iter()
                .filter_map(|d| d.get("path").and_then(Value::as_str))
                .filter_map(|path| relative(root, path))
                .collect(),
            _ => Vec::new(),
        };
        out.push(Package {
            name: name.to_owned(),
            dir,
            deps,
        });
    }
    Ok(out)
}

/// `path` relative to `root`, both absolute; `None` when it lies outside.
fn relative(root: &str, path: &str) -> Option<String>
{
    let root = root.trim_end_matches('/');
    let rest = path.strip_prefix(root)?.strip_prefix('/')?;
    Some(rest.trim_end_matches('/').to_owned())
}

/// Each tracked Rust source that names a file it reads, with that file,
/// both relative to the root.
fn source_reads(root: &Path) -> Result<Vec<(String, String)>>
{
    let output = Command::new("git")
        .args(["grep", "-n", "-E", READ_PATTERN, "--", "*.rs"])
        .current_dir(root)
        .output()
        .context("failed to launch git grep")?;
    let hits = match output.status.code()
    {
        Some(0) => String::from_utf8_lossy(&output.stdout).into_owned(),
        // `git grep` exits 1 when nothing matches.
        Some(1) => String::new(),
        _ => bail!(
            "git grep failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    };
    Ok(hits.lines().filter_map(read_of).collect())
}

/// The source and the file read of one `git grep -n` hit
/// (`<source>:<line>:<text>`), the file resolved against the source's
/// directory as `include!` and an outer `#[path]` resolve it; `None` when
/// the hit names no string literal, or one that leaves the repository.
fn read_of(hit: &str) -> Option<(String, String)>
{
    let (source, rest) = hit.split_once(':')?;
    let (_, text) = rest.split_once(':')?;
    let literal = text.split_once('"')?.1.split_once('"')?.0;
    let dir = source.rsplit_once('/').map_or("", |(dir, _)| dir);
    let mut parts: Vec<&str> = dir.split('/').filter(|p| !p.is_empty()).collect();
    for part in literal.split('/')
    {
        match part
        {
            "" | "." =>
            {}
            ".." =>
            {
                parts.pop()?;
            }
            _ => parts.push(part),
        }
    }
    Some((source.to_owned(), parts.join("/")))
}

/// Run `git` with `args` in `root` and return its output; fails on a
/// non-zero exit, naming git's error.
fn git(root: &Path, args: &[&str]) -> Result<String>
{
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .context("failed to launch git")?;
    if !output.status.success()
    {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn package(name: &str, dir: &str, deps: &[&str]) -> Package
    {
        Package {
            name: name.to_owned(),
            dir: dir.to_owned(),
            deps: deps.iter().map(|d| (*d).to_owned()).collect(),
        }
    }

    /// `proto` depends on `abi`, which depends on `util`; `other` depends on
    /// `util` and nothing depends on it.
    fn workspace(reads: &[(&str, &str)]) -> Workspace
    {
        Workspace::new(
            vec![
                package("proto", "shared/proto", &["abi/abi"]),
                package("abi", "abi/abi", &["shared/util"]),
                package("util", "shared/util", &[]),
                package("other", "services/other", &["shared/util"]),
            ],
            reads,
        )
    }

    fn first(reads: &[(&str, &str)], changed: &[&str]) -> Option<Input>
    {
        let changed: Vec<String> = changed.iter().map(|c| (*c).to_owned()).collect();
        workspace(reads)
            .first_input("shared/proto", &changed)
            .unwrap()
    }

    fn input(file: &str, package: &str) -> Input
    {
        Input {
            file: file.to_owned(),
            package: package.to_owned(),
        }
    }

    // Defect caught: a package's own file, or one of a dependency it reaches
    // directly or through another, not taken as its input; or a file of a
    // package outside its closure, or of a sibling whose name extends its
    // directory's, taken as one.
    #[test]
    fn a_package_s_inputs_are_its_closure_s_directories()
    {
        assert_eq!(
            first(&[], &["shared/proto/src/lib.rs"]),
            Some(input("shared/proto/src/lib.rs", "proto"))
        );
        assert_eq!(
            first(&[], &["abi/abi/src/lib.rs"]),
            Some(input("abi/abi/src/lib.rs", "abi"))
        );
        assert_eq!(
            first(&[], &["shared/util/Cargo.toml"]),
            Some(input("shared/util/Cargo.toml", "util"))
        );
        assert_eq!(
            first(
                &[],
                &[
                    "services/other/src/main.rs",
                    "shared/proto-tool/x.rs",
                    "docs/a.md"
                ]
            ),
            None
        );
    }

    // Defect caught: a file a package's source reads from outside its
    // directory (`include_str!` of a shared table, say) changing with no
    // input found.
    #[test]
    fn a_file_a_package_reads_from_outside_its_directory_is_its_input()
    {
        let reads = [("shared/util/src/lib.rs", "rootfs/config/table.conf")];
        assert_eq!(
            first(&reads, &["rootfs/config/table.conf"]),
            Some(input("rootfs/config/table.conf", "util"))
        );
        // A read by a package outside the closure is not its input.
        let reads = [("services/other/src/main.rs", "rootfs/config/table.conf")];
        assert_eq!(first(&reads, &["rootfs/config/table.conf"]), None);
    }

    // Defect caught: a directory no package lies in answered as having no
    // changed input, so its caller skips what it cannot judge.
    #[test]
    fn a_directory_with_no_package_fails()
    {
        let refused = workspace(&[])
            .first_input("loose", &["loose/src/lib.rs".to_owned()])
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("no workspace package lies in loose"),
            "{refused}"
        );
    }

    // Defect caught: a read resolved against another directory than its
    // source's, so the selection watches the wrong file.
    #[test]
    fn a_read_resolves_against_its_sources_directory()
    {
        assert_eq!(
            read_of(r#"shared/policy/src/lib.rs:217:    include_str!("../../../rootfs/x.conf");"#),
            Some((
                "shared/policy/src/lib.rs".to_owned(),
                "rootfs/x.conf".to_owned()
            ))
        );
        assert_eq!(
            read_of(r#"core/kernel/src/arch/mod.rs:13:#[path = "x86_64/mod.rs"]"#),
            Some((
                "core/kernel/src/arch/mod.rs".to_owned(),
                "core/kernel/src/arch/x86_64/mod.rs".to_owned()
            ))
        );
        // A mention with no string literal, or one that leaves the
        // repository, names no file.
        assert_eq!(
            read_of("a/src/lib.rs:3://! uses include_str! for its table"),
            None
        );
        assert_eq!(read_of(r#"a.rs:1:include_str!("../../x")"#), None);
    }

    // Defect caught: a package's directory or its path dependencies taken
    // as absolute, or a dependency from the registry taken as a package,
    // so no changed path, which git gives relative, matches them.
    #[test]
    fn cargo_metadata_gives_each_package_its_directory_and_path_dependencies()
    {
        let metadata = json::parse(
            r#"{"workspace_root": "/w", "packages": [
                {"name": "proto", "manifest_path": "/w/shared/proto/Cargo.toml",
                 "dependencies": [{"name": "abi", "path": "/w/abi/abi"},
                                  {"name": "serde"}]},
                {"name": "abi", "manifest_path": "/w/abi/abi/Cargo.toml", "dependencies": []}
            ]}"#,
        )
        .unwrap();
        assert_eq!(
            packages_of(&metadata).unwrap(),
            [
                package("proto", "shared/proto", &["abi/abi"]),
                package("abi", "abi/abi", &[]),
            ]
        );
    }
}
