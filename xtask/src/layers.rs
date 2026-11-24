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
//!
//! The image side places each file a disk image holds ([`INSTALL_ROWS`]): the
//! layer it serves and whether it is a test feature. The pack composes each
//! kind of image from it ([`Image`], `crate::disk`), and the image check holds
//! each image it reads back to its kind (`crate::image_check`).

use std::path::Path;

use crate::affected::{Package, WORKSPACE_WIDE, Workspace, under};
use crate::error::{Context as _, Result, bail};
use crate::rust_src;

/// A layer of the tree, lowest first. A change in one can affect its own
/// harness and the harnesses above it, never one below.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
        "rootfs/config/svcmgr/services/sessiond.svc",
        Class::Layer(Layer::Programs),
        "sessiond's default recipe, whose session leader is the shell; the services layer \
         stages its own",
    ),
    (
        "rootfs/config/svcmgr/services/terminal.svc",
        Class::Layer(Layer::Programs),
        "the terminal's recipe",
    ),
    (
        "rootfs/config/svcmgr/tests/usertest.svc",
        Class::Layer(Layer::Programs),
        "usertest's recipe",
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

// ── The image side ───────────────────────────────────────────────────────────

/// What a row installs: a part of the system, or a test feature (a harness, a
/// tester, a fixture, a test driver, or a recipe, class or data file only a
/// test reads), which the default image leaves out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role
{
    System,
    Test,
}

/// What an installed file is to the image that holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Install
{
    /// The layer whose harness the file serves.
    pub layer: Layer,
    /// Whether it is a system file or a test feature.
    pub role: Role,
}

/// The install rows: a file of the sysroot, or a directory ending in `/`,
/// by its path relative to the sysroot, with the layer it serves, its role and
/// why. An installed file takes the longest row that holds it; a file no row
/// holds fails the pack that would write it, so the record is extended, never
/// guessed. A host test holds each row to the source row of what installs
/// there: the layer of the crate or the `rootfs/` file, and the test role
/// exactly when the source is a harness's, a tester's, a fixture's or a test
/// driver's.
///
/// A test feature installs under `tests/`, apart from one a component under
/// test finds by its install path, which installs where that component looks
/// and takes its own row: `test-dma`, which devmgr binds from the drivers
/// directory, and the test recipes, classes and data the services read from
/// their own directories.
pub const INSTALL_ROWS: &[(&str, Layer, Role, &str)] = &[
    (
        "boot/",
        Layer::Kernel,
        Role::System,
        "the kernel and the bootloader",
    ),
    (
        "config/",
        Layer::Services,
        Role::System,
        "the services' configuration",
    ),
    (
        "config/boot/",
        Layer::Kernel,
        Role::System,
        "the boot-time policy the bootloader reads",
    ),
    (
        "config/bundle/ktest.list",
        Layer::Kernel,
        Role::Test,
        "the ktest bundle's list",
    ),
    (
        "config/devmgr/tests/",
        Layer::Services,
        Role::Test,
        "the test device classes",
    ),
    (
        "config/svcmgr/tests/",
        Layer::Services,
        Role::Test,
        "the recipes of the harnesses and the fixtures",
    ),
    (
        "crash/",
        Layer::Services,
        Role::System,
        "crashd's core-dump directory",
    ),
    (
        "data/",
        Layer::Services,
        Role::System,
        "the data partition's files",
    ),
    (
        "data/crasher-boot/",
        Layer::Services,
        Role::Test,
        "the crasher fixture's boot-fault token",
    ),
    (
        "data/svctest/",
        Layer::Services,
        Role::Test,
        "svctest's file-system data",
    ),
    (
        "data/test.txt",
        Layer::Services,
        Role::Test,
        "the file the file-system tests read",
    ),
    ("programs/", Layer::Programs, Role::System, "the programs"),
    (
        "services/",
        Layer::Services,
        Role::System,
        "init, the services, the drivers and the filesystems",
    ),
    (
        "services/drivers/test-dma",
        Layer::Services,
        Role::Test,
        "the test DMA driver, which devmgr binds from the drivers directory",
    ),
    ("tests/ktest", Layer::Kernel, Role::Test, "ktest"),
    ("tests/svctest", Layer::Services, Role::Test, "svctest"),
    ("tests/ubench", Layer::Services, Role::Test, "ubench"),
    (
        "tests/fixtures/",
        Layer::Services,
        Role::Test,
        "the services layer's fixtures",
    ),
    (
        "tests/drivers/",
        Layer::Services,
        Role::Test,
        "the test drivers",
    ),
    (
        "tests/programs/",
        Layer::Programs,
        Role::Test,
        "the programs' testers",
    ),
    ("tests/usertest", Layer::Programs, Role::Test, "usertest"),
];

/// The directory of svcmgr's recipes, which are judged by what they name as
/// well as by their row ([`recipe`]).
const RECIPES: &str = "config/svcmgr/";

/// The install row of `path`, relative to the sysroot, by its name alone.
#[must_use]
pub fn install_row(path: &str) -> Option<Install>
{
    INSTALL_ROWS
        .iter()
        .filter(|(row, _, _, _)| under(path, row))
        .max_by_key(|(row, _, _, _)| row.len())
        .map(|(_, layer, role, _)| Install {
            layer: *layer,
            role: *role,
        })
}

/// Place the installed file at `path`, relative to the sysroot, as an image
/// holds it: its install row and, for a recipe (a `.svc` file under
/// `config/svcmgr/`), what the recipe names ([`recipe`]), the higher layer
/// and the test role winning. `read` gives the file's bytes, a signed object
/// or not; it is called for a recipe alone.
///
/// # Errors
/// When no install row holds `path`, or a recipe cannot be read.
pub fn installed(path: &str, read: impl FnOnce() -> Result<Vec<u8>>) -> Result<Install>
{
    let Some(row) = install_row(path)
    else
    {
        bail!(
            "{path}: no install row of xtask/src/layers.rs places it, so no image may hold it; \
             add its row"
        );
    };
    let is_recipe = under(path, RECIPES)
        && Path::new(path)
            .extension()
            .is_some_and(|extension| extension == "svc");
    if !is_recipe
    {
        return Ok(row);
    }
    let object = read().with_context(|| format!("reading the recipe {path}"))?;
    let body = crate::signing::body_of(&object).with_context(|| format!("reading {path}"))?;
    // A recipe that is not UTF-8 (a tampered one, which the `signing` case
    // boots on purpose for svcmgr to refuse) is judged by the paths its
    // decodable text names: a byte that does not decode names no path.
    let text = String::from_utf8_lossy(body);
    let named = recipe(&text);
    Ok(Install {
        layer: row.layer.max(named.layer),
        role: if row.role == Role::Test || named.role == Role::Test
        {
            Role::Test
        }
        else
        {
            Role::System
        },
    })
}

/// What the recipe text `text` starts, by the install paths its lines name
/// (its `binary`, its `argv`, its `env`, its `namespace`; comment lines
/// aside): the highest layer of them, the services layer, which svcmgr is of,
/// at least; and the test role when it names a test feature. A path no install
/// row holds counts for nothing.
#[must_use]
pub fn recipe(text: &str) -> Install
{
    let mut named = Install {
        layer: Layer::Services,
        role: Role::System,
    };
    let lines = text
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'));
    for line in lines
    {
        for path in named_paths(line)
        {
            if let Some(install) = path.strip_prefix('/').and_then(install_row)
            {
                named.layer = named.layer.max(install.layer);
                if install.role == Role::Test
                {
                    named.role = Role::Test;
                }
            }
        }
    }
    named
}

/// The absolute paths `text` names: each run of path characters (letters,
/// digits, `_`, `-`, `.`, `/`) that starts with one `/` and follows no
/// path character, so `subtree:/data/a:LOOKUP` names `/data/a`, and neither
/// `a/programs/b` nor `https://host/programs` names a path under
/// `/programs`.
#[must_use]
pub fn named_paths(text: &str) -> Vec<&str>
{
    let is_path = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/');
    let mut paths = Vec::new();
    let mut previous: Option<char> = None;
    let mut chars = text.char_indices().peekable();
    while let Some((at, c)) = chars.next()
    {
        let starts = c == '/'
            && !previous.is_some_and(is_path)
            && chars
                .peek()
                .is_some_and(|&(_, next)| next != '/' && is_path(next));
        if starts
        {
            let end = text
                .get(at..)
                .and_then(|rest| rest.find(|c: char| !is_path(c)))
                .map_or(text.len(), |len| at.saturating_add(len));
            if let Some(path) = text.get(at..end)
            {
                paths.push(path);
            }
            while chars.peek().is_some_and(|&(next, _)| next < end)
            {
                chars.next();
            }
            previous = text.get(..end).and_then(|head| head.chars().next_back());
            continue;
        }
        previous = Some(c);
    }
    paths
}

/// What an image holds on its root and data partitions. The pack decides it
/// from the harness it boots and the recipes the sysroot stages
/// (`crate::disk`); the image check holds each image it reads back to it
/// (`crate::image_check`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Image
{
    /// The ktest image: its ESP carries the kernel layer's bundle, and its root
    /// and data partitions hold nothing.
    Kernel,
    /// The image of a services-layer harness, svctest's or ubench's: no file
    /// of the programs layer.
    Services,
    /// An image whose staged recipes name a test feature (usertest's, a case's
    /// fixture's): the whole system with its test features.
    Harness,
    /// The default image, which stages no test: the whole system and no test
    /// feature.
    Default,
}

impl Image
{
    /// Whether an image of this kind holds a file installed as `install`.
    #[must_use]
    pub fn holds(self, install: Install) -> bool
    {
        match self
        {
            Self::Kernel => false,
            Self::Services => install.layer <= Layer::Services,
            Self::Harness => true,
            Self::Default => install.role == Role::System,
        }
    }

    /// The kind as the pack's log names it.
    #[must_use]
    pub fn label(self) -> &'static str
    {
        match self
        {
            Self::Kernel => "kernel-layer image: the ESP alone",
            Self::Services => "services-layer image: no file of the programs layer",
            Self::Harness => "test image: the whole system and its test features",
            Self::Default => "default image: no test feature",
        }
    }
}

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

    // Defect caught: a recipe judged by its binary alone, so one that hands a
    // service a program in its argv, or leads it to a fixture, is taken for a
    // plain service; a commented-out line counted; or a path that only shares
    // a prefix with a layer's taken for that layer's.
    #[test]
    fn a_recipe_takes_the_highest_layer_and_the_test_role_of_what_it_names()
    {
        let services = Install {
            layer: Layer::Services,
            role: Role::System,
        };
        for (text, layer, role) in [
            ("binary = /services/vfsd\n", Layer::Services, Role::System),
            (
                "binary = /services/sessiond\nargv = sessiond /programs/shell\n",
                Layer::Programs,
                Role::System,
            ),
            (
                "binary = /services/sessiond\nargv = sessiond /tests/fixtures/programs/leader\n",
                Layer::Services,
                Role::Test,
            ),
            ("binary = /tests/usertest\n", Layer::Programs, Role::Test),
            (
                "binary = /services/x\nnamespace = subtree:/data/crasher-boot:LOOKUP\n",
                Layer::Services,
                Role::Test,
            ),
            ("binary = /tests/ktest\n", Layer::Services, Role::Test),
        ]
        {
            assert_eq!(recipe(text), Install { layer, role }, "{text}");
        }
        for text in [
            "# argv = x /programs/shell\nbinary = /services/x\n",
            "binary = /services/programsd\nargv = x a/programs/b https://host/programs\n",
            "binary = /programsx/a\nargv = x /tests/programsy /tests/usertest2\n",
        ]
        {
            assert_eq!(recipe(text), services, "{text}");
        }
    }

    // Defect caught: a path read from inside a word, a URL or a relative path,
    // or one cut short at a separator a recipe uses.
    #[test]
    fn named_paths_are_the_absolute_paths_at_a_word_start()
    {
        assert_eq!(named_paths("subtree:/data/a:LOOKUP"), ["/data/a"]);
        assert_eq!(named_paths("x=/p/q-1.2,/r /s"), ["/p/q-1.2", "/r", "/s"]);
        for none in ["a/programs/b", "https://host/x", "/", "// c", "x/ y"]
        {
            assert_eq!(named_paths(none), Vec::<&str>::new(), "{none}");
        }
    }

    // Defect caught: an install row shadowed by a shorter one, so a test
    // feature of a services directory is taken for a system file, the ktest
    // bundle for the init one's, or a tester for a program; or a path sharing
    // a prefix with a row placed by it.
    #[test]
    fn the_longest_install_row_places_an_installed_file()
    {
        let row = |path| install_row(path).map(|install| (install.layer, install.role));
        let (kernel, services, programs) = (Layer::Kernel, Layer::Services, Layer::Programs);
        let (system, test) = (Role::System, Role::Test);
        for (path, want) in [
            ("boot/kernel", Some((kernel, system))),
            ("config/boot/policy.conf", Some((kernel, system))),
            ("config/bundle/ktest.list", Some((kernel, test))),
            ("config/bundle/init.x86_64.list", Some((services, system))),
            ("config/svcmgr/tests/svctest.svc", Some((services, test))),
            ("services/drivers/test-dma", Some((services, test))),
            ("services/drivers/test-dmax", Some((services, system))),
            ("data/svctest/large.bin", Some((services, test))),
            ("data/notes", Some((services, system))),
            ("tests/ktest", Some((kernel, test))),
            ("tests/fixtures/programs/leader", Some((services, test))),
            ("tests/programs/hello", Some((programs, test))),
            ("tests/usertest", Some((programs, test))),
            ("programs/shell", Some((programs, system))),
            ("tests/usertest2", None),
            ("tests/other", None),
            ("stray", None),
        ]
        {
            assert_eq!(row(path), want, "{path}");
        }
        let refused = installed("stray/file", || Ok(Vec::new()))
            .unwrap_err()
            .to_string();
        assert!(refused.contains("stray/file: no install row"), "{refused}");
        // A recipe is judged by what it names as well as by its row.
        let staged = installed("config/svcmgr/services/usertest.svc", || {
            Ok(b"binary = /tests/usertest\n".to_vec())
        })
        .unwrap();
        assert_eq!((staged.layer, staged.role), (programs, test));
        // A recipe that is not UTF-8 (the `signing` case's tampered one) is
        // judged by the paths its decodable text names, not refused.
        let tampered = installed("config/svcmgr/services/timed.svc", || {
            Ok(b"binary = /services/timed\n\xff\nargv = timed /programs/shell\n".to_vec())
        })
        .unwrap();
        assert_eq!((tampered.layer, tampered.role), (programs, system));
    }

    // Defect caught: an image kind holding what it may not: a test feature on
    // the default image, a programs-layer file on a services-layer one,
    // anything on the kernel layer's root partition.
    #[test]
    fn each_image_holds_what_its_kind_allows()
    {
        let all = [Layer::Kernel, Layer::Services, Layer::Programs]
            .into_iter()
            .flat_map(|layer| [Role::System, Role::Test].map(|role| Install { layer, role }));
        for install in all
        {
            assert!(!Image::Kernel.holds(install), "{install:?}");
            assert_eq!(
                Image::Services.holds(install),
                install.layer != Layer::Programs,
                "{install:?}"
            );
            assert!(Image::Harness.holds(install), "{install:?}");
            assert_eq!(
                Image::Default.holds(install),
                install.role == Role::System,
                "{install:?}"
            );
        }
    }

    /// The source directories of the test features: the harnesses, the fixtures,
    /// the test drivers, and, by [`is_test_source`], every program's tester.
    const TEST_SOURCES: &[&str] = &[
        "core/ktest/",
        "services/svctest/",
        "services/ubench/",
        "services/fixtures/",
        "services/drivers/test-dma/",
        "services/drivers/test-fault/",
        "programs/usertest/",
    ];

    /// Whether the crate whose directory is `dir` (relative to the root) builds a
    /// test feature: it lies under one of [`TEST_SOURCES`], or it is a program's
    /// tester, a `tester` directory under `programs/`.
    fn is_test_source(dir: &str) -> bool
    {
        TEST_SOURCES.iter().any(|source| under(dir, source))
            || (under(dir, "programs/") && dir.trim_end_matches('/').ends_with("/tester"))
    }

    /// The layer the directory row of `dir` places a crate in, when one does.
    fn dir_layer(dir: &str) -> Option<Layer>
    {
        match longest(DIR_ROWS, dir)
        {
            Some((_, Class::Layer(layer), _)) => Some(*layer),
            _ => None,
        }
    }

    // Defect caught: a binary installed where its install row gives another
    // layer than its crate's, or a role other than its source's (a harness, a
    // tester or a fixture installed under /programs/ or among the services,
    // where the default image would keep it, or a system binary under
    // /tests/); a rootfs file whose install row disagrees with its source
    // row, so CI selection and the image composition differ on its layer; or
    // a file a build installs that no install row places, which would fail
    // every pack.
    #[test]
    fn every_installed_file_has_the_install_row_of_its_source()
    {
        let (root, files) = tracked();
        let ws = Workspace::load(&root).unwrap();
        let mut wrong = Vec::new();
        for arch in [crate::arch::Arch::X86_64, crate::arch::Arch::Riscv64]
        {
            for (name, install) in crate::commands::build::crate_installs(arch)
            {
                let package = ws
                    .package(name)
                    .unwrap_or_else(|| panic!("no crate {name}"));
                let role = if is_test_source(&package.dir)
                {
                    Role::Test
                }
                else
                {
                    Role::System
                };
                let want = dir_layer(&package.dir).map(|layer| Install { layer, role });
                if install_row(&install) != want
                {
                    wrong.push(format!(
                        "{install} (crate {name} in {}): row {:?}, source {want:?}",
                        package.dir,
                        install_row(&install)
                    ));
                }
            }
            for data in crate::sysroot::data_files(arch)
            {
                let install = data.install.trim_start_matches('/');
                let source = place(&ws, data.source, Presence::Present).unwrap().class;
                let row = install_row(install);
                if source != Class::Build && row.map(|row| Class::Layer(row.layer)) != Some(source)
                {
                    wrong.push(format!(
                        "{install} (from {}): row {row:?}, source {source:?}",
                        data.source
                    ));
                }
            }
        }
        for file in files.iter().filter(|f| {
            f.starts_with("rootfs/") && Path::new(f).file_name().is_none_or(|n| n != "README.md")
        })
        {
            let install = file.trim_start_matches("rootfs/");
            let source = place(&ws, file, Presence::Present).unwrap().class;
            match installed(install, || {
                std::fs::read(root.join(file)).context("reading")
            })
            {
                Ok(row) if source == Class::Build || Class::Layer(row.layer) == source =>
                {}
                Ok(row) => wrong.push(format!(
                    "{install} (from {file}): row {row:?}, source {source:?}"
                )),
                Err(e) => wrong.push(format!("{e:#}")),
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    // Defect caught: the ktest bundle carrying a file above the kernel layer,
    // which the kernel layer's image, whose root partition holds nothing,
    // could not serve; or the default bundle carrying a test feature or a
    // program.
    #[test]
    fn each_bundle_names_only_its_own_layer()
    {
        let (root, _) = tracked();
        let lists = root.join("rootfs").join(crate::bundle::LIST_DIR);
        for entry in std::fs::read_dir(&lists).unwrap()
        {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap().to_owned();
            let list = crate::bundle::parse_list(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let ktest = name == "ktest.list";
            for object in std::iter::once(&list.init).chain(&list.entries)
            {
                let row = install_row(object.trim_start_matches('/'))
                    .unwrap_or_else(|| panic!("{name}: {object} has no install row"));
                if ktest
                {
                    assert_eq!(row.layer, Layer::Kernel, "{name}: {object}");
                }
                else
                {
                    assert_eq!(
                        (row.layer <= Layer::Services, row.role),
                        (true, Role::System),
                        "{name}: {object}"
                    );
                }
            }
        }
    }

    // Defect caught: a crate depending, directly or through a shared crate,
    // on a crate of a higher layer, so a change to the higher layer reaches a
    // harness below it that no cell of that layer would run.
    #[test]
    fn no_crate_depends_on_a_crate_of_a_higher_layer()
    {
        let (root, _) = tracked();
        let ws = Workspace::load(&root).unwrap();
        let mut upward = Vec::new();
        for package in ws.packages()
        {
            let Some(own) = dir_layer(&package.dir)
            else
            {
                continue;
            };
            for dependency in ws.dependencies(&package.name).unwrap()
            {
                if dir_layer(&dependency.dir).is_some_and(|layer| layer > own)
                {
                    upward.push(format!("{} -> {}", package.name, dependency.name));
                }
            }
        }
        assert!(upward.is_empty(), "{upward:#?}");
    }

    /// The contents of the string literals of the Rust source `text`, as
    /// written (escapes not decoded): plain, byte and C strings and their raw
    /// forms; comments, character literals and lifetimes left out.
    fn string_literals(text: &str) -> Vec<&str>
    {
        let bytes = text.as_bytes();
        let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
        let mut literals = Vec::new();
        let mut at = 0;
        while at < bytes.len()
        {
            let rest = &bytes[at..];
            if rest.starts_with(b"//")
            {
                at += rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
            }
            else if rest.starts_with(b"/*")
            {
                at = block_comment_end(bytes, at);
            }
            else if is_ident(rest[0])
            {
                // A word, which may prefix a raw string: r, br, cr. The other
                // prefixes (b, c) leave the quote next.
                let word = rest
                    .iter()
                    .position(|&b| !is_ident(b))
                    .unwrap_or(rest.len());
                let hashes = rest[word..].iter().take_while(|&&b| b == b'#').count();
                let open = at + word + hashes;
                if matches!(&rest[..word], b"r" | b"br" | b"cr") && bytes.get(open) == Some(&b'"')
                {
                    let close: Vec<u8> = std::iter::once(b'"')
                        .chain(std::iter::repeat_n(b'#', hashes))
                        .collect();
                    let body = open + 1;
                    let end = bytes[body..]
                        .windows(close.len())
                        .position(|w| w == close.as_slice())
                        .map_or(bytes.len(), |p| body + p);
                    literals.push(&text[body..end]);
                    at = (end + close.len()).min(bytes.len());
                }
                else
                {
                    at += word;
                }
            }
            else if rest[0] == b'"'
            {
                let body = at + 1;
                let mut end = body;
                while end < bytes.len() && bytes[end] != b'"'
                {
                    end += if bytes[end] == b'\\' { 2 } else { 1 };
                }
                let end = end.min(bytes.len());
                literals.push(&text[body..end]);
                at = end + 1;
            }
            else if rest[0] == b'\''
            {
                at = quote_end(text, at);
            }
            else
            {
                at += 1;
            }
        }
        literals
    }

    /// The byte after the block comment of `bytes` that opens at `at`, the
    /// comments nested in it included.
    fn block_comment_end(bytes: &[u8], mut at: usize) -> usize
    {
        let mut depth = 0usize;
        while at < bytes.len()
        {
            if bytes[at..].starts_with(b"/*")
            {
                depth += 1;
                at += 2;
            }
            else if bytes[at..].starts_with(b"*/")
            {
                depth -= 1;
                at += 2;
                if depth == 0
                {
                    break;
                }
            }
            else
            {
                at += 1;
            }
        }
        at
    }

    /// The byte after the character literal (`'x'`, `'\n'`, `'\u{..}'`) that
    /// opens at `at` of `text`, or after the quote of a lifetime there.
    fn quote_end(text: &str, at: usize) -> usize
    {
        let rest = &text.as_bytes()[at..];
        if rest.get(1) == Some(&b'\\')
        {
            return at + 3 + rest[3..].iter().position(|&b| b == b'\'').unwrap_or(0) + 1;
        }
        let ch = text[at + 1..].chars().next().map_or(1, char::len_utf8);
        if rest.get(1 + ch) == Some(&b'\'')
        {
            at + 2 + ch
        }
        else
        {
            at + 1
        }
    }

    // Defect caught: a string inside a comment, or one that follows a
    // character literal, a lifetime or a raw string, read wrongly, so the scan
    // of a source misses a literal or reads code as one.
    #[test]
    fn string_literals_are_read_as_written()
    {
        let source = r##"
            // "in a comment"
            /* "in /* a nested */ block" */
            fn f<'a>(x: &'a str) -> char { let _ = '"'; let _ = '\''; 'q' }
            let a = "one \" two";
            let b = r#"raw "quoted" /programs/x"#;
            let c = b"bytes";
            let d = br"raw bytes";
            let e = for_r"x";
        "##;
        assert_eq!(
            string_literals(source),
            [
                r#"one \" two"#,
                r#"raw "quoted" /programs/x"#,
                "bytes",
                "raw bytes",
                "x"
            ]
        );
    }

    // Defect caught: a source below the programs layer (svctest, a service,
    // the runtime, a shared crate they link, the kernel layer) naming an
    // install path of the programs layer, so svctest starts a program or a
    // program's tester, or a service reaches for one, which no services-layer
    // image holds. Comments may name such paths; code may not. The kernel
    // layer's own bound is its image's: the ktest image holds nothing above
    // the kernel layer (`crate::image_check`), while the bootloader names the
    // init bundle's services by design.
    #[test]
    fn no_services_layer_source_names_an_install_path_of_the_programs_layer()
    {
        let (root, files) = tracked();
        let ws = Workspace::load(&root).unwrap();
        let mut named = Vec::new();
        for file in files
            .iter()
            .filter(|f| Path::new(f).extension().is_some_and(|e| e == "rs"))
        {
            let Class::Layer(own) = place(&ws, file, Presence::Present).unwrap().class
            else
            {
                continue;
            };
            let text = std::fs::read_to_string(root.join(file)).unwrap();
            for literal in string_literals(&text)
            {
                for path in named_paths(literal)
                {
                    let higher = path
                        .strip_prefix('/')
                        .and_then(install_row)
                        .filter(|install| {
                            install.layer == Layer::Programs && own != Layer::Programs
                        });
                    if let Some(install) = higher
                    {
                        named.push(format!("{file} ({own:?}): {path} ({:?})", install.layer));
                    }
                }
            }
        }
        assert!(named.is_empty(), "{named:#?}");
    }
}
