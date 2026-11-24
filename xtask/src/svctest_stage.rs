// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/svctest_stage.rs

//! The staging of the services-layer boots: the svctest boot
//! (`cargo xtask mkdisk --svctest <set>`) and the ubench boot
//! (`cargo xtask mkdisk --ubench`). Both stage the services layer
//! ([`stage_services_layer`]): every recipe in `config/svcmgr/services/`
//! that starts a file of the programs layer ([`PROGRAMS_LAYER`]), or another
//! services-layer harness, is removed, and sessiond's svctest recipe, whose
//! session leader is the fixture `/tests/fixtures/programs/leader`, is staged
//! over the default one. A pack of a sysroot so staged omits the programs
//! layer's files from the image ([`services_layer`], `crate::disk`), so the
//! image runs no program.
//!
//! The svctest boot then stages svctest's recipe and the fixtures of one
//! named set ([`svctest_fixtures::Set`]) copied from `config/svcmgr/tests/`
//! into `config/svcmgr/services/`, every other fixture's recipe removed from
//! it; crashd's svctest recipe over the default one, or, for a set that
//! stages no crashd, no crashd recipe; the test class files of
//! `config/devmgr/tests/` copied into `config/devmgr/classes/`; and the
//! set's record, and its phase selection when it makes one, written into the
//! staged recipe's `env` line, which svctest checks the image against
//! (docs/testing.md § Gating). The ubench boot stages ubench's recipe.

use std::fs;
use std::path::Path;

use svctest_fixtures::{CRASHD_RECIPE, ENV, Fixture, NONE, PHASES_ENV, Set};

use crate::error::{Context as _, Result, bail};
use crate::signing::body_of;
use crate::util::step;

crate::argparse::value_enum! {
    /// The fixture set the svctest boot co-stages.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SvctestSet
    {
        /// Every fixture: crasher, crasher-worker, crasher-boot, memhog,
        /// reserve-creator and stopsrc, as the canonical svctest cells stage
        /// them
        #[value(name = "ci")]
        Ci,
        /// memhog, reserve-creator and stopsrc, as the burn-in svctest cell
        /// stages them
        #[value(name = "burn-in")]
        BurnIn,
        /// No fixture: every fixture phase skips
        #[value(name = "none")]
        None,
        /// No fixture and no crashd, and only the `crash_endpoint` phase runs
        /// after svctest's startup phases: procmgr's crash endpoint with
        /// svctest as the crash service
        #[value(name = "crash-endpoint")]
        CrashEndpoint,
    }
}

impl SvctestSet
{
    /// The set of the fixtures crate.
    pub fn set(self) -> Set
    {
        match self
        {
            SvctestSet::Ci => Set::Ci,
            SvctestSet::BurnIn => Set::BurnIn,
            SvctestSet::None => Set::None,
            SvctestSet::CrashEndpoint => Set::CrashEndpoint,
        }
    }
}

/// The programs layer's files, relative to the sysroot: the programs, their
/// testers, the programs-layer harness and its recipe. A services-layer image
/// holds none of them.
pub const PROGRAMS_LAYER: [&str; 4] = [
    "programs",
    "tests/programs",
    "tests/usertest",
    "config/svcmgr/tests/usertest.svc",
];

/// The sysroot-relative directory of the test recipes.
const TESTS_DIR: &str = "config/svcmgr/tests";
/// The sysroot-relative directory svcmgr starts the recipes of.
const SERVICES_DIR: &str = "config/svcmgr/services";
/// The sysroot-relative directory of the test class files.
const TEST_CLASSES_DIR: &str = "config/devmgr/tests";
/// The sysroot-relative directory devmgr reads class files from.
const CLASSES_DIR: &str = "config/devmgr/classes";
/// svctest's recipe's file name.
const SVCTEST_RECIPE: &str = "svctest.svc";
/// ubench's recipe's file name.
const UBENCH_RECIPE: &str = "ubench.svc";
/// sessiond's recipe's file name, the default's and the svctest one's.
const SESSIOND_RECIPE: &str = "sessiond.svc";
/// The recipes of the services-layer harnesses, one of which, staged, makes
/// a sysroot's image a services-layer image.
const SERVICES_LAYER_HARNESSES: [&str; 2] = [SVCTEST_RECIPE, UBENCH_RECIPE];

/// Whether the sysroot at `sysroot` stages a services-layer harness, whose
/// image omits the files of [`PROGRAMS_LAYER`].
pub fn services_layer(sysroot: &Path) -> bool
{
    let services = sysroot.join(SERVICES_DIR);
    SERVICES_LAYER_HARNESSES
        .iter()
        .any(|recipe| services.join(recipe).is_file())
}

/// Stage the ubench boot in `sysroot` (see the module documentation).
///
/// # Errors
///
/// As [`stage_services_layer`] fails, when ubench's test recipe is missing,
/// or on an I/O failure.
pub fn stage_ubench(sysroot: &Path) -> Result<()>
{
    stage_services_layer(sysroot)?;
    copy_recipe(sysroot, UBENCH_RECIPE)?;
    step("ubench staged on the services layer");
    Ok(())
}

/// Stage the services layer in `sysroot`: remove each staged recipe whose
/// `binary` is a file of [`PROGRAMS_LAYER`] or a services-layer harness, and
/// stage sessiond's svctest recipe over the default one.
///
/// # Errors
///
/// When sessiond's svctest recipe is missing, a staged recipe cannot be read,
/// or on an I/O failure.
fn stage_services_layer(sysroot: &Path) -> Result<()>
{
    let services = sysroot.join(SERVICES_DIR);
    let entries =
        fs::read_dir(&services).with_context(|| format!("reading {}", services.display()))?;
    for entry in entries
    {
        let path = entry
            .with_context(|| format!("reading {}", services.display()))?
            .path();
        if path.extension().is_none_or(|e| e != "svc") || !path.is_file()
        {
            continue;
        }
        let harness = path
            .file_name()
            .is_some_and(|name| SERVICES_LAYER_HARNESSES.iter().any(|h| name == *h));
        let object = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let body = body_of(&object).with_context(|| format!("reading {}", path.display()))?;
        if harness || binary_of(body).is_some_and(in_programs_layer)
        {
            fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        }
    }
    copy_recipe(sysroot, SESSIOND_RECIPE)
}

/// The value of the recipe `body`'s `binary` line, when it has one.
fn binary_of(body: &[u8]) -> Option<&str>
{
    std::str::from_utf8(body).ok()?.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key.trim() == "binary").then(|| value.trim())
    })
}

/// Whether the absolute path `binary` is a file of [`PROGRAMS_LAYER`], or
/// lies under a directory of it.
fn in_programs_layer(binary: &str) -> bool
{
    let Some(relative) = binary.strip_prefix('/')
    else
    {
        return false;
    };
    PROGRAMS_LAYER.iter().any(|layer| {
        relative == *layer
            || relative
                .strip_prefix(layer)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// Copy the test recipe `name` from [`TESTS_DIR`] into [`SERVICES_DIR`].
///
/// # Errors
///
/// When the test recipe is missing, or on an I/O failure.
fn copy_recipe(sysroot: &Path, name: &str) -> Result<()>
{
    let source = sysroot.join(TESTS_DIR).join(name);
    if !source.is_file()
    {
        bail!("no test recipe at {}", source.display());
    }
    let staged = sysroot.join(SERVICES_DIR).join(name);
    fs::copy(&source, &staged)
        .with_context(|| format!("copying {} -> {}", source.display(), staged.display()))?;
    Ok(())
}

/// Remove the staged recipe `name` from [`SERVICES_DIR`], when staged.
///
/// # Errors
///
/// On an I/O failure other than the recipe's absence.
fn remove_recipe(sysroot: &Path, name: &str) -> Result<()>
{
    let staged = sysroot.join(SERVICES_DIR).join(name);
    match fs::remove_file(&staged)
    {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", staged.display())),
    }
}

/// Stage the svctest boot of `set` in `sysroot` (see the module
/// documentation). The staged recipe is written unsigned, for the sign that
/// precedes every pack.
///
/// # Errors
///
/// When a recipe the set needs or a test class directory is missing, when
/// svctest's recipe carries no single `env` line or already a record, and
/// as [`stage_services_layer`] fails, or on an I/O failure.
pub fn stage(sysroot: &Path, set: Set) -> Result<()>
{
    stage_services_layer(sysroot)?;
    let tests = sysroot.join(TESTS_DIR);
    for fixture in Fixture::ALL
    {
        if set.fixtures().contains(&fixture)
        {
            if !tests.join(fixture.recipe()).is_file()
            {
                bail!(
                    "the {} set's fixture {} has no recipe at {}",
                    set.name(),
                    fixture.name(),
                    tests.join(fixture.recipe()).display()
                );
            }
            copy_recipe(sysroot, fixture.recipe())?;
        }
        else
        {
            remove_recipe(sysroot, fixture.recipe())?;
        }
    }
    if set.stages_crashd()
    {
        copy_recipe(sysroot, CRASHD_RECIPE)?;
    }
    else
    {
        remove_recipe(sysroot, CRASHD_RECIPE)?;
    }

    let source = tests.join(SVCTEST_RECIPE);
    let object = fs::read(&source).with_context(|| format!("reading {}", source.display()))?;
    let body = body_of(&object).with_context(|| format!("reading {}", source.display()))?;
    let text =
        std::str::from_utf8(body).with_context(|| format!("{} is not UTF-8", source.display()))?;
    let mut pairs = vec![(ENV, record(set))];
    if let Some(phases) = set.phases()
    {
        pairs.push((PHASES_ENV, phases.to_owned()));
    }
    let recipe = with_env(text, &pairs).with_context(|| format!("staging {}", source.display()))?;
    let staged = sysroot.join(SERVICES_DIR).join(SVCTEST_RECIPE);
    fs::write(&staged, recipe).with_context(|| format!("writing {}", staged.display()))?;

    let class_dir = sysroot.join(TEST_CLASSES_DIR);
    let classes = sysroot.join(CLASSES_DIR);
    let entries =
        fs::read_dir(&class_dir).with_context(|| format!("reading {}", class_dir.display()))?;
    for entry in entries
    {
        let source = entry
            .with_context(|| format!("reading {}", class_dir.display()))?
            .path();
        if source.extension().is_some_and(|e| e == "class") && source.is_file()
        {
            let name = source.file_name().context("a class file has a name")?;
            let dst = classes.join(name);
            fs::copy(&source, &dst)
                .with_context(|| format!("copying {} -> {}", source.display(), dst.display()))?;
        }
    }
    step(&format!(
        "svctest staged on the services layer with the {} fixture set ({})",
        set.name(),
        pairs
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    ));
    Ok(())
}

/// The record of `set` svctest parses (`svctest_fixtures::Declared::parse`):
/// its fixtures' names separated by commas, or [`NONE`].
fn record(set: Set) -> String
{
    if set.fixtures().is_empty()
    {
        return NONE.to_owned();
    }
    set.fixtures()
        .iter()
        .map(|f| f.name())
        .collect::<Vec<_>>()
        .join(",")
}

/// The recipe text `recipe` with each `<key>=<value>` of `pairs` appended to
/// its `env` line, in order.
///
/// # Errors
///
/// When the recipe has no `env` line or several, or its `env` line already
/// sets a key of `pairs`.
fn with_env(recipe: &str, pairs: &[(&str, String)]) -> Result<String>
{
    let is_env = |line: &str| {
        line.split_once('=')
            .is_some_and(|(key, _)| key.trim() == "env")
    };
    let count = recipe.lines().filter(|line| is_env(line)).count();
    if count != 1
    {
        bail!("the recipe has {count} env lines, not one");
    }
    let mut out = String::with_capacity(recipe.len());
    for line in recipe.split_inclusive('\n')
    {
        let (text, end) = line
            .strip_suffix('\n')
            .map_or((line, ""), |text| (text, "\n"));
        if is_env(text)
        {
            let value = text.split_once('=').map_or("", |(_, value)| value);
            for (key, _) in pairs
            {
                let set_already = value
                    .split_whitespace()
                    .any(|pair| pair.split_once('=').is_some_and(|(k, _)| k == *key));
                if set_already
                {
                    bail!("the recipe's env line already sets {key}");
                }
            }
            out.push_str(text.trim_end());
            for (key, value) in pairs
            {
                out.push(' ');
                out.push_str(key);
                out.push('=');
                out.push_str(value);
            }
        }
        else
        {
            out.push_str(text);
        }
        out.push_str(end);
    }
    Ok(out)
}

#[cfg(test)]
mod tests
{
    use std::path::PathBuf;

    use svctest_fixtures::Declared;

    use super::*;

    fn scratch(tag: &str) -> PathBuf
    {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "seraph-svctest-stage-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    /// A sysroot holding every fixture's test recipe, svctest's, ubench's,
    /// crashd's and sessiond's, one test class file, and the services and
    /// classes directories; the services directory holds a default crashd
    /// and sessiond, a program's recipe (the terminal's) and a service's.
    fn sysroot(tag: &str) -> PathBuf
    {
        let root = scratch(tag);
        let tests = root.join(TESTS_DIR);
        fs::create_dir_all(&tests).unwrap();
        for fixture in Fixture::ALL
        {
            fs::write(tests.join(fixture.recipe()), fixture.name()).unwrap();
        }
        fs::write(
            tests.join(SVCTEST_RECIPE),
            "# svctest\nbinary = /tests/svctest\nenv       = SERAPH_TEST=1\nrestart = never\n",
        )
        .unwrap();
        fs::write(tests.join(UBENCH_RECIPE), "binary = /tests/ubench\n").unwrap();
        fs::write(tests.join(CRASHD_RECIPE), "test crashd").unwrap();
        fs::write(tests.join(SESSIOND_RECIPE), "test sessiond").unwrap();
        let services = root.join(SERVICES_DIR);
        fs::create_dir_all(&services).unwrap();
        fs::write(services.join(CRASHD_RECIPE), "binary = /services/crashd\n").unwrap();
        fs::write(
            services.join(SESSIOND_RECIPE),
            "binary = /services/sessiond\n",
        )
        .unwrap();
        fs::write(
            services.join("terminal.svc"),
            "binary    = /programs/terminal\n",
        )
        .unwrap();
        fs::write(services.join("timed.svc"), "binary = /services/timed\n").unwrap();
        fs::create_dir_all(root.join(TEST_CLASSES_DIR)).unwrap();
        fs::write(root.join(TEST_CLASSES_DIR).join("test-dma.class"), "dma").unwrap();
        fs::create_dir_all(root.join(CLASSES_DIR)).unwrap();
        root
    }

    /// The value of `key` the staged svctest recipe's `env` line carries.
    fn staged_env(root: &Path, key: &str) -> Option<String>
    {
        let recipe = fs::read_to_string(root.join(SERVICES_DIR).join(SVCTEST_RECIPE)).unwrap();
        let prefix = format!("{key}=");
        recipe
            .split_whitespace()
            .find_map(|pair| pair.strip_prefix(prefix.as_str()))
            .map(str::to_owned)
    }

    /// The staged recipe `name`, when staged.
    fn staged(root: &Path, name: &str) -> Option<String>
    {
        fs::read_to_string(root.join(SERVICES_DIR).join(name)).ok()
    }

    // Defect caught: a staging that co-stages another set than it records, or
    // keeps a fixture an earlier staging of another set left, so svctest's
    // record and the image disagree; or one that stages crashd for the set
    // that selects the crash_endpoint phase, or none for a set of every phase.
    #[test]
    fn each_set_stages_exactly_its_fixtures_and_crashd_and_records_them()
    {
        for set in Set::ALL
        {
            let root = sysroot(set.name());
            let services = root.join(SERVICES_DIR);
            // An earlier staging of every fixture.
            for fixture in Fixture::ALL
            {
                fs::write(services.join(fixture.recipe()), "earlier").unwrap();
            }
            stage(&root, set).unwrap();
            for fixture in Fixture::ALL
            {
                let want = set
                    .fixtures()
                    .contains(&fixture)
                    .then(|| fixture.name().to_owned());
                assert_eq!(staged(&root, fixture.recipe()), want, "{set:?} {fixture:?}");
            }
            let record = staged_env(&root, ENV).unwrap();
            assert_eq!(
                Declared::parse(&record).unwrap(),
                Declared::of(set.fixtures()),
                "{set:?}: {record}"
            );
            assert_eq!(
                staged_env(&root, PHASES_ENV).as_deref(),
                set.phases(),
                "{set:?}"
            );
            assert_eq!(
                staged(&root, CRASHD_RECIPE).as_deref(),
                set.stages_crashd().then_some("test crashd"),
                "{set:?}"
            );
            assert_eq!(
                fs::read_to_string(root.join(CLASSES_DIR).join("test-dma.class")).unwrap(),
                "dma"
            );
            let recipe = staged(&root, SVCTEST_RECIPE).unwrap();
            assert!(
                recipe.starts_with("# svctest\nbinary = /tests/svctest\n")
                    && recipe.ends_with("\nrestart = never\n"),
                "{recipe}"
            );
            fs::remove_dir_all(&root).unwrap();
        }
    }

    // Defect caught: a services-layer boot that still starts a program (the
    // terminal, a hand-staged usertest), leads its sessions with a program, or
    // keeps the other services-layer harness of an earlier staging; or a
    // sysroot so staged whose pack keeps the programs layer.
    #[test]
    fn the_services_layer_runs_no_program()
    {
        for ubench in [false, true]
        {
            let root = sysroot(
                if ubench
                {
                    "layer-ubench"
                }
                else
                {
                    "layer-svctest"
                },
            );
            fs::write(
                root.join(SERVICES_DIR).join("usertest.svc"),
                "binary = /tests/usertest\n",
            )
            .unwrap();
            let earlier = if ubench
            {
                SVCTEST_RECIPE
            }
            else
            {
                UBENCH_RECIPE
            };
            fs::write(root.join(SERVICES_DIR).join(earlier), "an earlier staging").unwrap();
            assert!(services_layer(&root));
            if ubench
            {
                stage_ubench(&root).unwrap();
            }
            else
            {
                stage(&root, Set::Ci).unwrap();
            }
            assert_eq!(staged(&root, "terminal.svc"), None);
            assert_eq!(staged(&root, "usertest.svc"), None);
            assert_eq!(
                staged(&root, SESSIOND_RECIPE).as_deref(),
                Some("test sessiond")
            );
            assert!(staged(&root, "timed.svc").is_some());
            assert_eq!(staged(&root, SVCTEST_RECIPE).is_some(), !ubench);
            assert_eq!(staged(&root, UBENCH_RECIPE).is_some(), ubench);
            assert!(services_layer(&root));
            fs::remove_dir_all(&root).unwrap();
        }
        let root = sysroot("layer-default");
        assert!(!services_layer(&root));
        fs::remove_dir_all(&root).unwrap();
    }

    // Defect caught: a programs-layer file judged a service's, or a service
    // judged a program because its name shares a prefix with a layer's.
    #[test]
    fn a_binary_is_in_the_programs_layer_only_under_one_of_its_paths()
    {
        for binary in [
            "/programs/shell",
            "/tests/programs/hello",
            "/tests/usertest",
        ]
        {
            assert!(in_programs_layer(binary), "{binary}");
        }
        for binary in [
            "/services/timed",
            "/tests/svctest",
            "/tests/usertest2",
            "/programsx/a",
            "/tests/fixtures/programs/leader",
            "programs/shell",
        ]
        {
            assert!(!in_programs_layer(binary), "{binary}");
        }
        assert_eq!(
            binary_of(b"# c\nbinary  =  /programs/a \n"),
            Some("/programs/a")
        );
        assert_eq!(binary_of(b"argv = a\n"), None);
    }

    // Defect caught: a set whose fixture recipe is renamed or gone staged
    // without it, so the boot runs with the fixture's phase reduced.
    #[test]
    fn a_set_whose_fixture_has_no_recipe_is_refused()
    {
        let root = sysroot("missing");
        fs::remove_file(root.join(TESTS_DIR).join(Fixture::Memhog.recipe())).unwrap();
        let error = format!("{:#}", stage(&root, Set::BurnIn).unwrap_err());
        assert!(error.contains("fixture memhog has no recipe"), "{error}");
        stage(&root, Set::None).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    // Defect caught: a record appended to no line svcmgr passes as the
    // environment, or a second record svctest would read in place of the
    // first.
    #[test]
    fn a_recipe_without_one_env_line_free_of_a_record_is_refused()
    {
        let memhog = [(ENV, "memhog".to_owned())];
        assert_eq!(
            with_env("binary = /x\nenv = A=1  \n", &memhog).unwrap(),
            "binary = /x\nenv = A=1 SVCTEST_FIXTURES=memhog\n"
        );
        assert_eq!(
            with_env(
                "env = A=1",
                &[
                    (ENV, NONE.to_owned()),
                    (PHASES_ENV, "crash_endpoint".to_owned())
                ]
            )
            .unwrap(),
            "env = A=1 SVCTEST_FIXTURES=none SVCTEST_PHASES=crash_endpoint"
        );
        for refused in [
            "binary = /x\n",
            "env = A=1\nenv = B=2\n",
            "env = A=1 SVCTEST_FIXTURES=memhog\n",
        ]
        {
            assert!(with_env(refused, &memhog).is_err(), "{refused:?}");
        }
        with_env("env = SVCTEST_PHASES=x\n", &[(PHASES_ENV, "y".to_owned())]).unwrap_err();
    }

    /// The repository's recipe `dir/name`, its comment and blank lines
    /// dropped and the spacing of each `key = value` line normalised.
    fn settings(dir: &str, name: &str) -> Vec<String>
    {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("rootfs")
            .join(dir)
            .join(name);
        fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                line.split_once('=')
                    .map_or(line.to_owned(), |(key, value)| {
                        let words: Vec<&str> = value.split_whitespace().collect();
                        format!("{} = {}", key.trim(), words.join(" "))
                    })
            })
            .collect()
    }

    // Defect caught: a set naming a fixture whose recipe the repository does
    // not ship, or svctest's repository recipe carrying a record of its own,
    // which every staging would refuse; or a svctest recipe of crashd or
    // sessiond drifted from the default it stands in for, so the services
    // layer tests another service than the image ships.
    #[test]
    fn the_repository_ships_each_sets_recipes()
    {
        let tests = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("rootfs")
            .join(TESTS_DIR);
        for set in Set::ALL
        {
            for fixture in set.fixtures()
            {
                assert!(
                    tests.join(fixture.recipe()).is_file(),
                    "{}: no {}",
                    set.name(),
                    fixture.recipe()
                );
            }
        }
        let recipe = fs::read_to_string(tests.join(SVCTEST_RECIPE)).unwrap();
        with_env(
            &recipe,
            &[(ENV, NONE.to_owned()), (PHASES_ENV, "x".to_owned())],
        )
        .unwrap();
        assert!(tests.join(UBENCH_RECIPE).is_file());

        // Each differs from its default in the one line that makes it the
        // services layer's: crashd's names crashme for core dumps, sessiond's
        // leads sessions with the leader fixture.
        for (name, default_line, test_line) in [
            (
                CRASHD_RECIPE,
                "env = CORE_DUMP=no CRASHD_OOM_STALL_MS=10000",
                "env = CORE_DUMP=crashme CRASHD_OOM_STALL_MS=10000",
            ),
            (
                SESSIOND_RECIPE,
                "argv = sessiond /programs/shell",
                "argv = sessiond /tests/fixtures/programs/leader",
            ),
        ]
        {
            let default = settings(SERVICES_DIR, name);
            let test = settings(TESTS_DIR, name);
            assert!(
                default.iter().any(|l| l == default_line),
                "{name}: {default:?}"
            );
            let swapped: Vec<String> = default
                .iter()
                .map(|l| {
                    if l == default_line
                    {
                        test_line.to_owned()
                    }
                    else
                    {
                        l.clone()
                    }
                })
                .collect();
            assert_eq!(test, swapped, "{name}");
        }
    }
}
