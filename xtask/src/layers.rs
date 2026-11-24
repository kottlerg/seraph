// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/layers.rs

//! The record of what each path of the tree is: the layer it lies in, or the
//! class outside the layers it takes, and so what a change to it can affect.
//! `cargo xtask cells` places each path a change touches here and owes the CI
//! cells of the most demanding class (docs/testing.md § Coverage tiers).
//!
//! A path is placed in this order: Markdown is documentation; an explicit row
//! ([`FILE_ROWS`], or an input of every build, [`WORKSPACE_WIDE`]), the
//! longest that holds it; the workspace package it lies in, which takes the
//! most demanding directory row ([`DIR_ROWS`]) among itself and every package
//! whose dependencies reach it, so that a crate under `shared/` takes the
//! lowest layer of the crates that link it; or, in no package, the directory
//! row that holds it. A path a tracked source reads (`include_str!` and the
//! like) also takes that source's class. A path nothing places fails the
//! command, so the record is extended, never guessed; a deleted one, for which
//! no row can be added, owes every cell.

use std::path::Path;

use crate::affected::{Package, WORKSPACE_WIDE, Workspace, under};
use crate::error::{Result, bail};
use crate::rust_src;

/// A layer of the tree. A change in one can affect its own harness and the
/// harnesses above it, never one below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer
{
    /// The bootloader, the kernel, the ABI crates and ktest.
    Kernel,
    /// init, the services, the drivers and filesystems, svctest, and the
    /// runtime and `std` port.
    Services,
    /// The programs and their testers.
    Programs,
}

/// What a path is, as far as what a change to it can affect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class
{
    /// Markdown, and the files no build and no tool of the cells reads: the
    /// assistant's instruction files, the Issue templates, the license.
    Docs,
    /// What only the host tests check: the xtask commands no CI cell runs, and
    /// the formatter and editor settings.
    Host,
    /// A file of one layer.
    Layer(Layer),
    /// An input of every cell: the workspace manifest and lock, the toolchain
    /// pin, Cargo's configuration, the workflows, the lint settings, and the
    /// parts of xtask a cell runs, the cell selection among them.
    Build,
}

impl Class
{
    /// How much a change to a path of the class can affect: a change owes
    /// what its most demanding path owes.
    #[must_use]
    pub fn demand(self) -> u8
    {
        match self
        {
            Self::Docs => 0,
            Self::Host => 1,
            Self::Layer(Layer::Programs) => 2,
            Self::Layer(Layer::Services) => 3,
            Self::Layer(Layer::Kernel) => 4,
            Self::Build => 5,
        }
    }

    /// The class as the selection's log names it.
    #[must_use]
    pub fn label(self) -> &'static str
    {
        match self
        {
            Self::Docs => "docs",
            Self::Host => "host",
            Self::Layer(Layer::Kernel) => "kernel",
            Self::Layer(Layer::Services) => "services",
            Self::Layer(Layer::Programs) => "programs",
            Self::Build => "build",
        }
    }
}

/// A placed path: its class and the reason, as the selection's log gives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placed
{
    pub class: Class,
    pub why: String,
}

/// The reason of the xtask files no CI cell runs.
const HOST_TOOL: &str = "xtask code no CI cell runs";

/// The explicit rows: a file, or a directory ending in `/`, with its class and
/// why. A path takes the longest row that holds it, before any package.
///
/// The xtask rows draw the line inside xtask: a file a validate or bench cell
/// runs (`build`, `mkdisk`, `run`, `test --cell` and its cases,
/// `bench-check`, `clean`, and what they call), and the cell selection, is
/// the xtask package's, [`Class::Build`]; the files below are the rest, which
/// no Build file of xtask uses but its command dispatch (`main.rs`, `cli.rs`,
/// `commands/mod.rs`), as a host test checks. A new xtask file is Build until
/// a row here says otherwise.
pub const FILE_ROWS: &[(&str, Class, &str)] = &[
    (".claude/", Class::Docs, "the assistant's instruction files"),
    (
        ".github/ISSUE_TEMPLATE/",
        Class::Docs,
        "the Issue templates",
    ),
    ("LICENSE", Class::Docs, "the license text"),
    (".github/", Class::Build, "the workflows and their actions"),
    (
        "clippy.toml",
        Class::Build,
        "the lint settings of every build",
    ),
    (
        "shared/clippy.toml",
        Class::Build,
        "the lint settings of the shared crates, which every layer links",
    ),
    (".gitignore", Class::Host, "git's ignore list"),
    (".editorconfig", Class::Host, "the editor settings"),
    (".clang-format", Class::Host, "the C formatter's settings"),
    (
        "rustfmt.toml",
        Class::Host,
        "the Rust formatter's settings, which the host tests check",
    ),
    (
        "rootfs/config/boot/",
        Class::Layer(Layer::Kernel),
        "the boot-time policy the bootloader reads",
    ),
    (
        "rootfs/config/bundle/ktest.list",
        Class::Layer(Layer::Kernel),
        "the ktest bundle",
    ),
    (
        "rootfs/config/bundle/",
        Class::Layer(Layer::Services),
        "the init bundle",
    ),
    (
        "rootfs/config/devmgr/",
        Class::Layer(Layer::Services),
        "devmgr's device classes",
    ),
    (
        "rootfs/config/svcmgr/",
        Class::Layer(Layer::Services),
        "svcmgr's recipes",
    ),
    (
        "rootfs/data/",
        Class::Layer(Layer::Services),
        "the data partition's files",
    ),
    ("xtask/src/argparse/reference.rs", Class::Host, HOST_TOOL),
    ("xtask/src/argparse/reference/", Class::Host, HOST_TOOL),
    (
        "xtask/src/commands/bench_baseline.rs",
        Class::Host,
        HOST_TOOL,
    ),
    ("xtask/src/commands/capture_acpi.rs", Class::Host, HOST_TOOL),
    (
        "xtask/src/commands/compare_images.rs",
        Class::Host,
        HOST_TOOL,
    ),
    (
        "xtask/src/commands/crypto_vectors.rs",
        Class::Host,
        HOST_TOOL,
    ),
    ("xtask/src/commands/fuzz.rs", Class::Host, HOST_TOOL),
    ("xtask/src/commands/hook.rs", Class::Host, HOST_TOOL),
    ("xtask/src/commands/host.rs", Class::Host, HOST_TOOL),
    ("xtask/src/commands/issue.rs", Class::Host, HOST_TOOL),
    ("xtask/src/commands/kani.rs", Class::Host, HOST_TOOL),
    ("xtask/src/commands/lint_docs/", Class::Host, HOST_TOOL),
    ("xtask/src/commands/orch.rs", Class::Host, HOST_TOOL),
    ("xtask/src/commands/path_account.rs", Class::Host, HOST_TOOL),
    ("xtask/src/commands/pr_check.rs", Class::Host, HOST_TOOL),
    (
        "xtask/src/commands/release_scope.rs",
        Class::Host,
        HOST_TOOL,
    ),
    ("xtask/src/commands/review.rs", Class::Host, HOST_TOOL),
    ("xtask/src/commands/threat_scope.rs", Class::Host, HOST_TOOL),
    (
        "xtask/src/commands/trust_request.rs",
        Class::Host,
        HOST_TOOL,
    ),
    ("xtask/src/diag.rs", Class::Host, HOST_TOOL),
    ("xtask/src/markdown.rs", Class::Host, HOST_TOOL),
    ("xtask/src/path_account.rs", Class::Host, HOST_TOOL),
    ("xtask/src/path_record.rs", Class::Host, HOST_TOOL),
    ("xtask/src/tasklist.rs", Class::Host, HOST_TOOL),
];

/// The directory rows: the class of a package whose directory one holds, and
/// of a file in no package under it. `shared/` has none, so a crate there
/// takes the class of the crates that link it.
pub const DIR_ROWS: &[(&str, Class, &str)] = &[
    ("core/", Class::Layer(Layer::Kernel), "the kernel layer"),
    (
        "abi/",
        Class::Layer(Layer::Kernel),
        "the kernel layer's ABI crates",
    ),
    (
        "services/",
        Class::Layer(Layer::Services),
        "the services layer",
    ),
    (
        "runtime/",
        Class::Layer(Layer::Services),
        "the runtime and std port",
    ),
    (
        "programs/",
        Class::Layer(Layer::Programs),
        "the programs layer",
    ),
    (
        "xtask/fuzz/",
        Class::Host,
        "the fuzz engine and targets, which only the fuzz job runs",
    ),
    (
        "xtask/path-account-plugin/",
        Class::Host,
        "the path-account plugin, which no CI cell loads",
    ),
    (
        "xtask/",
        Class::Build,
        "xtask, which builds, stages and boots every cell's image",
    ),
];

/// The longest row of `rows` that holds `path`.
fn longest<'a>(
    rows: &'a [(&'a str, Class, &'a str)],
    path: &str,
) -> Option<&'a (&'a str, Class, &'a str)>
{
    rows.iter()
        .filter(|(row, _, _)| under(path, row))
        .max_by_key(|(row, _, _)| row.len())
}

/// Whether a changed path is in the working tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence
{
    /// The path is in the working tree.
    Present,
    /// The change deleted the path.
    Deleted,
}

/// Place `path` (relative to the root), which the working tree holds or the
/// change deleted, as `presence` says.
///
/// # Errors
/// An existing path that nothing places: a file in no row and no package, or
/// a crate no placed crate links.
pub fn place(workspace: &Workspace, path: &str, presence: Presence) -> Result<Placed>
{
    let mut placed = place_alone(workspace, path);
    for reader in workspace.readers_of(path)
    {
        if let Some(by) = place_alone(workspace, reader)
        {
            let read = Placed {
                class: by.class,
                why: format!("read by {reader} ({})", by.why),
            };
            placed = Some(more_demanding(placed, read));
        }
    }
    match placed
    {
        Some(placed) => Ok(placed),
        None if presence == Presence::Deleted => Ok(Placed {
            class: Class::Build,
            why: "deleted, and no row places it".to_owned(),
        }),
        None => bail!(
            "{path}: no row of xtask/src/layers.rs places it (a file in no package and no \
             row, or a crate no placed crate links); add its row"
        ),
    }
}

/// The more demanding of `a` and `b`; `a` on a tie.
fn more_demanding(a: Option<Placed>, b: Placed) -> Placed
{
    match a
    {
        Some(a) if a.class.demand() >= b.class.demand() => a,
        Some(_) | None => b,
    }
}

/// Place `path` by its own name: Markdown, its explicit row, its package, or
/// its directory row; `None` when none holds it.
fn place_alone(workspace: &Workspace, path: &str) -> Option<Placed>
{
    let is_markdown = Path::new(path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("md"));
    if is_markdown
    {
        return Some(Placed {
            class: Class::Docs,
            why: "Markdown".to_owned(),
        });
    }
    if WORKSPACE_WIDE.iter().any(|wide| under(path, wide))
    {
        return Some(Placed {
            class: Class::Build,
            why: "an input of every build".to_owned(),
        });
    }
    if let Some((_, class, why)) = longest(FILE_ROWS, path)
    {
        return Some(Placed {
            class: *class,
            why: (*why).to_owned(),
        });
    }
    if let Some(package) = workspace.package_of(path)
    {
        return place_package(workspace, package);
    }
    longest(DIR_ROWS, path).map(|(_, class, why)| Placed {
        class: *class,
        why: (*why).to_owned(),
    })
}

/// The class of `package`'s files: the most demanding directory row among it
/// and every package whose dependencies reach it, the std port counting as a
/// package of `runtime/ruststd/` that links the crates std depends on
/// (`rust_src::std_workspace_packages`), which cargo's metadata does not
/// show; `None` when none has a row.
fn place_package(workspace: &Workspace, package: &Package) -> Option<Placed>
{
    let linkers = workspace.dependents(&package.name)?;
    let std_links = linkers
        .iter()
        .any(|linker| rust_src::std_workspace_packages().any(|std| std == linker.name));
    let mut rows: Vec<(&(&str, Class, &str), &str)> = linkers
        .iter()
        .filter_map(|linker| longest(DIR_ROWS, &linker.dir).map(|row| (row, linker.name.as_str())))
        .collect();
    if std_links
    {
        rows.extend(longest(DIR_ROWS, STD_PORT).map(|row| (row, "the std port")));
    }
    let (row, linker) = rows.into_iter().reduce(|best, next| {
        if next.0.1.demand() > best.0.1.demand()
        {
            next
        }
        else
        {
            best
        }
    })?;
    let (_, class, why) = row;
    let why = if linker == package.name
    {
        format!("{why} (crate {})", package.name)
    }
    else
    {
        format!("crate {}, linked by {linker}: {why}", package.name)
    };
    Some(Placed { class: *class, why })
}

/// The std port's directory.
const STD_PORT: &str = "runtime/ruststd/";

#[cfg(test)]
mod tests
{
    use std::process::Command;

    use super::*;

    fn package(name: &str, dir: &str, deps: &[&str]) -> Package
    {
        Package {
            name: name.to_owned(),
            dir: dir.to_owned(),
            deps: deps.iter().map(|d| (*d).to_owned()).collect(),
        }
    }

    /// A tree of each kind of crate: the kernel and ktest, an ABI crate, a
    /// shared crate the kernel links, one only services and programs link,
    /// one only a fuzz target links, one nothing links, a service, a program,
    /// a service's crate xtask links, and xtask.
    fn workspace(reads: &[(&str, &str)]) -> Workspace
    {
        Workspace::new(
            vec![
                package("kernel", "core/kernel", &["shared/kshared", "abi/syscall"]),
                package("ktest", "core/ktest", &["abi/syscall"]),
                package("syscall-abi", "abi/syscall", &[]),
                package("kshared", "shared/kshared", &[]),
                package("svcshared", "shared/svcshared", &[]),
                package(
                    "vfsd",
                    "services/vfsd",
                    &["shared/svcshared", "services/vfsd/gpt"],
                ),
                package("vfsd-gpt", "services/vfsd/gpt", &[]),
                package(
                    "shell",
                    "programs/shell",
                    &["shared/svcshared", "abi/syscall"],
                ),
                package("xtask", "xtask", &["services/vfsd/gpt"]),
                package("targets", "xtask/fuzz/targets", &["shared/fuzzonly"]),
                package("fuzzonly", "shared/fuzzonly", &[]),
                package("lonely", "shared/lonely", &[]),
                package("registry-client", "shared/registry-client", &["shared/ipc"]),
                package("ipc", "shared/ipc", &[]),
            ],
            reads,
        )
    }

    fn class(ws: &Workspace, path: &str) -> Class
    {
        place(ws, path, Presence::Present).unwrap().class
    }

    // Defect caught: a crate placed by its own directory alone, so a shared
    // crate the kernel links owes no ktest, or one only services link owes
    // ktest; or a crate under a layer directory placed in another layer.
    #[test]
    fn a_crate_takes_the_lowest_layer_of_itself_and_the_crates_that_link_it()
    {
        let ws = workspace(&[]);
        let kernel = Class::Layer(Layer::Kernel);
        let services = Class::Layer(Layer::Services);
        assert_eq!(class(&ws, "core/kernel/src/main.rs"), kernel);
        assert_eq!(class(&ws, "abi/syscall/src/lib.rs"), kernel);
        assert_eq!(class(&ws, "shared/kshared/src/lib.rs"), kernel);
        assert_eq!(class(&ws, "services/vfsd/src/main.rs"), services);
        assert_eq!(class(&ws, "shared/svcshared/Cargo.toml"), services);
        assert_eq!(
            class(&ws, "programs/shell/src/main.rs"),
            Class::Layer(Layer::Programs)
        );
        assert_eq!(class(&ws, "shared/fuzzonly/src/lib.rs"), Class::Host);
        let why = place(&ws, "shared/kshared/src/lib.rs", Presence::Present)
            .unwrap()
            .why;
        assert!(why.contains("linked by kernel"), "{why}");
    }

    // Defect caught: a crate xtask links taken at its own layer, so a change
    // to the GPT reader every pack's image check uses owes no ktest cell.
    #[test]
    fn a_crate_xtask_links_owes_what_xtask_owes()
    {
        let ws = workspace(&[]);
        assert_eq!(class(&ws, "services/vfsd/gpt/src/lib.rs"), Class::Build);
        assert_eq!(class(&ws, "xtask/src/commands/build.rs"), Class::Build);
        assert_eq!(
            class(&ws, "xtask/baselines/bench/icount/x86_64/ENV"),
            Class::Build
        );
        assert_eq!(class(&ws, "xtask/src/commands/pr_check.rs"), Class::Host);
        assert_eq!(
            class(&ws, "xtask/src/commands/lint_docs/cells.rs"),
            Class::Host
        );
    }

    // Defect caught: a crate only the std port links, which cargo's metadata
    // shows no dependent of, refused as unplaced or placed below the
    // services layer, so a change to it owes no svctest boot.
    #[test]
    fn a_crate_the_std_port_links_is_in_the_services_layer()
    {
        let ws = workspace(&[]);
        for path in ["shared/registry-client/src/lib.rs", "shared/ipc/src/lib.rs"]
        {
            let placed = place(&ws, path, Presence::Present).unwrap();
            assert_eq!(placed.class, Class::Layer(Layer::Services), "{path}");
            assert!(placed.why.contains("the std port"), "{}", placed.why);
        }
    }

    // Defect caught: an explicit row shadowed by a shorter one or by the
    // package, so the ktest bundle is taken as the init bundle's, or a
    // workflow as documentation; or an input of every build missed.
    #[test]
    fn the_longest_explicit_row_places_a_path_before_its_package()
    {
        let ws = workspace(&[]);
        assert_eq!(
            class(&ws, "rootfs/config/bundle/ktest.list"),
            Class::Layer(Layer::Kernel)
        );
        assert_eq!(
            class(&ws, "rootfs/config/bundle/init.x86_64.list"),
            Class::Layer(Layer::Services)
        );
        assert_eq!(class(&ws, ".github/workflows/build-test.yml"), Class::Build);
        assert_eq!(class(&ws, ".github/ISSUE_TEMPLATE/config.yml"), Class::Docs);
        assert_eq!(class(&ws, "Cargo.lock"), Class::Build);
        assert_eq!(class(&ws, ".cargo/config.toml"), Class::Build);
        assert_eq!(class(&ws, "rustfmt.toml"), Class::Host);
    }

    // Defect caught: Markdown in a crate taken as the crate's, so a README
    // change boots every cell; or an instruction file not taken as
    // documentation.
    #[test]
    fn markdown_and_the_instruction_files_are_documentation()
    {
        let ws = workspace(&[]);
        assert_eq!(class(&ws, "core/kernel/README.md"), Class::Docs);
        assert_eq!(class(&ws, "docs/testing.md"), Class::Docs);
        assert_eq!(class(&ws, ".claude/settings.json"), Class::Docs);
        assert_eq!(class(&ws, ".github/pull_request_template.md"), Class::Docs);
    }

    // Defect caught: a file a crate embeds placed by its own name alone, so a
    // change to it owes less than the crate that builds it in.
    #[test]
    fn a_file_a_source_reads_takes_that_source_s_class()
    {
        let ws = workspace(&[
            ("core/kernel/src/table.rs", "docs/table.md"),
            (
                "xtask/src/argparse/reference.rs",
                "xtask/src/argparse/reference/help.txt",
            ),
        ]);
        let read = place(&ws, "docs/table.md", Presence::Present).unwrap();
        assert_eq!(read.class, Class::Layer(Layer::Kernel));
        assert!(
            read.why.contains("read by core/kernel/src/table.rs"),
            "{}",
            read.why
        );
        assert_eq!(
            class(&ws, "xtask/src/argparse/reference/help.txt"),
            Class::Host
        );
    }

    // Defect caught: a path nothing places taken as owing nothing, so a new
    // directory's change boots no cell; or a deleted crate, which no row can
    // be added for, failing every run that deletes it.
    #[test]
    fn a_path_nothing_places_fails_and_a_deleted_one_owes_every_cell()
    {
        let ws = workspace(&[]);
        for path in [
            "tools/new.sh",
            "shared/lonely/src/lib.rs",
            "shared/loose.rs",
        ]
        {
            let refused = place(&ws, path, Presence::Present).unwrap_err().to_string();
            assert!(
                refused.contains(path) && refused.contains("add its row"),
                "{refused}"
            );
        }
        assert_eq!(
            place(&ws, "shared/gone/src/lib.rs", Presence::Deleted)
                .unwrap()
                .class,
            Class::Build
        );
        // A deleted path a row places keeps its class.
        assert_eq!(
            place(&ws, "programs/old/src/main.rs", Presence::Deleted)
                .unwrap()
                .class,
            Class::Layer(Layer::Programs)
        );
    }

    /// The repository's root and its tracked files.
    fn tracked() -> (std::path::PathBuf, Vec<String>)
    {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let out = Command::new("git")
            .args(["ls-files"])
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(out.status.success());
        let files = String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        (root, files)
    }

    // Defect caught: a file of the tree no row places (a new top-level
    // directory, a crate moved where no row reaches, a crate nothing links),
    // which would fail CI's selection on the first change to it instead of
    // the change that added it.
    #[test]
    fn every_tracked_file_of_the_repository_is_placed()
    {
        let (root, files) = tracked();
        let ws = Workspace::load(&root).unwrap();
        let unplaced: Vec<String> = files
            .iter()
            .filter_map(|f| {
                place(&ws, f, Presence::Present)
                    .err()
                    .map(|e| e.to_string())
            })
            .collect();
        assert!(unplaced.is_empty(), "{unplaced:#?}");
    }

    // Defect caught: a row left behind by a move or a rename, which then
    // places nothing while the moved path falls to another row.
    #[test]
    fn every_row_holds_a_tracked_file()
    {
        let (_, files) = tracked();
        let stale: Vec<&str> = FILE_ROWS
            .iter()
            .chain(DIR_ROWS)
            .map(|(row, _, _)| *row)
            .filter(|row| !files.iter().any(|f| under(f, row)))
            .collect();
        assert!(
            stale.is_empty(),
            "rows that hold no tracked file: {stale:?}"
        );
    }

    /// The names of the kernel-layer crates among `packages`.
    fn kernel_layer<'a>(packages: &[&'a Package]) -> Vec<&'a str>
    {
        packages
            .iter()
            .filter(|p| {
                longest(DIR_ROWS, &p.dir).is_some_and(|(_, c, _)| *c == Class::Layer(Layer::Kernel))
            })
            .map(|p| p.name.as_str())
            .collect()
    }

    // Defect caught: a kernel-layer crate linking a runtime crate, so a
    // change to the runtime, which the record places in the services layer,
    // reaches a ktest image that no ktest cell then boots; or a crate std
    // links placed by the std port alone when a kernel-layer crate links it
    // too. The dependency graph decides, not the directory: a crate xtask
    // links is an input of every build, whatever its layer.
    #[test]
    fn the_runtime_is_linked_by_no_kernel_layer_crate()
    {
        let (root, _) = tracked();
        let ws = Workspace::load(&root).unwrap();
        let services = Class::Layer(Layer::Services);
        let kernel = Class::Layer(Layer::Kernel);
        let class_of = |package: &Package| {
            let manifest = format!("{}/Cargo.toml", package.dir);
            place(&ws, &manifest, Presence::Present).unwrap().class
        };
        let runtime: Vec<&Package> = ws
            .packages()
            .iter()
            .filter(|p| under(&p.dir, "runtime/"))
            .collect();
        assert_ne!(runtime.len(), 0, "no runtime/ package");
        for package in runtime
        {
            let linkers = kernel_layer(&ws.dependents(&package.name).unwrap());
            assert!(
                linkers.is_empty(),
                "{} is linked by kernel-layer crate(s) {linkers:?}",
                package.name
            );
            let class = class_of(package);
            assert!(
                class == services || class == Class::Build,
                "{}: {class:?}",
                package.name
            );
        }
        for name in rust_src::std_workspace_packages()
        {
            let package = ws.package(name).unwrap();
            let class = class_of(package);
            if kernel_layer(&ws.dependents(name).unwrap()).is_empty()
            {
                assert!(
                    class == services || class == Class::Build,
                    "{name}: {class:?}"
                );
            }
            else
            {
                assert!(
                    class == kernel || class == Class::Build,
                    "{name}: {class:?}"
                );
            }
        }
    }

    /// The files of xtask that only dispatch commands, naming every command's
    /// module.
    const DISPATCH: &[&str] = &[
        "xtask/src/main.rs",
        "xtask/src/cli.rs",
        "xtask/src/commands/mod.rs",
    ];

    /// The module a Host row of `xtask/src/` names: the file's stem or the
    /// directory's name.
    fn module_of(row: &str) -> Option<&str>
    {
        let rest = row.strip_prefix("xtask/src/")?.trim_end_matches('/');
        let last = rest.rsplit('/').next()?;
        Some(last.strip_suffix(".rs").unwrap_or(last))
    }

    /// Whether `text` names `module` of xtask's crate root or of its commands:
    /// a `crate::`, `crate::commands::` or `super::` path to it, or a name in
    /// the braces of a `use crate::` or `use super::` group.
    fn names_module(text: &str, module: &str) -> bool
    {
        let word = |s: &str| {
            s.split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .any(|w| w == module)
        };
        let paths = [
            format!("crate::{module}::"),
            format!("crate::commands::{module}::"),
            format!("super::{module}::"),
        ];
        paths.iter().any(|p| text.contains(p.as_str()))
            || text
                .split("use ")
                .skip(1)
                .filter_map(|u| u.split_once(';').map(|(stmt, _)| stmt))
                .filter(|stmt| stmt.starts_with("crate::") || stmt.starts_with("super::"))
                .filter_map(|stmt| stmt.split_once('{').map(|(_, group)| group))
                .any(word)
    }

    // Defect caught: a file a cell runs calling code its row calls host-only,
    // so a change to that code owes no cell though a cell runs it.
    #[test]
    fn no_xtask_file_a_cell_runs_uses_a_host_only_module()
    {
        let (root, files) = tracked();
        let ws = Workspace::load(&root).unwrap();
        let host: Vec<&str> = FILE_ROWS
            .iter()
            .filter(|(row, class, _)| *class == Class::Host && row.starts_with("xtask/src/"))
            .filter_map(|(row, _, _)| module_of(row))
            .collect();
        let mut uses = Vec::new();
        for file in files.iter().filter(|f| {
            f.starts_with("xtask/src/")
                && Path::new(f).extension().is_some_and(|e| e == "rs")
                && !DISPATCH.contains(&f.as_str())
                && place(&ws, f, Presence::Present).unwrap().class == Class::Build
        })
        {
            let text = std::fs::read_to_string(root.join(file)).unwrap();
            for module in &host
            {
                if names_module(&text, module)
                {
                    uses.push(format!("{file} uses {module}"));
                }
            }
        }
        assert!(uses.is_empty(), "{uses:#?}");
    }
}
