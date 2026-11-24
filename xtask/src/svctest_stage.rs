// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/svctest_stage.rs

//! The staging of the svctest boot (`cargo xtask mkdisk --svctest <set>`):
//! svctest's recipe and the fixtures of one named set
//! ([`svctest_fixtures::Set`]) copied from `config/svcmgr/tests/` into
//! `config/svcmgr/services/`, every other fixture's recipe removed from it,
//! the test class files of `config/devmgr/tests/` copied into
//! `config/devmgr/classes/`, and the set's record written into the staged
//! recipe's `env` line, which svctest checks the image against
//! (docs/testing.md § Gating).

use std::fs;
use std::path::Path;

use svctest_fixtures::{ENV, Fixture, NONE, Set};

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
        }
    }
}

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

/// Stage the svctest boot of `set` in `sysroot` (see the module
/// documentation). The staged recipe is written unsigned, for the sign that
/// precedes every pack.
///
/// # Errors
///
/// When a recipe the set needs or a test class directory is missing, when
/// svctest's recipe carries no single `env` line or already a record, or on
/// an I/O failure.
pub fn stage(sysroot: &Path, set: Set) -> Result<()>
{
    let tests = sysroot.join(TESTS_DIR);
    let services = sysroot.join(SERVICES_DIR);
    for fixture in Fixture::ALL
    {
        let staged = services.join(fixture.recipe());
        if set.fixtures().contains(&fixture)
        {
            let source = tests.join(fixture.recipe());
            if !source.is_file()
            {
                bail!(
                    "the {} set's fixture {} has no recipe at {}",
                    set.name(),
                    fixture.name(),
                    source.display()
                );
            }
            fs::copy(&source, &staged)
                .with_context(|| format!("copying {} -> {}", source.display(), staged.display()))?;
        }
        else
        {
            match fs::remove_file(&staged)
            {
                Ok(()) =>
                {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound =>
                {}
                Err(e) => return Err(e).with_context(|| format!("removing {}", staged.display())),
            }
        }
    }

    let source = tests.join(SVCTEST_RECIPE);
    let object = fs::read(&source).with_context(|| format!("reading {}", source.display()))?;
    let body = body_of(&object).with_context(|| format!("reading {}", source.display()))?;
    let text =
        std::str::from_utf8(body).with_context(|| format!("{} is not UTF-8", source.display()))?;
    let recipe =
        with_record(text, &record(set)).with_context(|| format!("staging {}", source.display()))?;
    let staged = services.join(SVCTEST_RECIPE);
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
        "svctest staged with the {} fixture set ({ENV}={})",
        set.name(),
        record(set)
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

/// The recipe text `recipe` with `<ENV>=<record>` appended to its `env`
/// line.
///
/// # Errors
///
/// When the recipe has no `env` line or several, or its `env` line already
/// sets [`ENV`].
fn with_record(recipe: &str, record: &str) -> Result<String>
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
            let set_already = text.split_once('=').is_some_and(|(_, value)| {
                value
                    .split_whitespace()
                    .any(|pair| pair.split_once('=').is_some_and(|(key, _)| key == ENV))
            });
            if set_already
            {
                bail!("the recipe's env line already sets {ENV}");
            }
            out.push_str(text.trim_end());
            out.push(' ');
            out.push_str(ENV);
            out.push('=');
            out.push_str(record);
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

    /// A sysroot holding every fixture's test recipe, svctest's, one test
    /// class file, and the services and classes directories.
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
        fs::create_dir_all(root.join(SERVICES_DIR)).unwrap();
        fs::create_dir_all(root.join(TEST_CLASSES_DIR)).unwrap();
        fs::write(root.join(TEST_CLASSES_DIR).join("test-dma.class"), "dma").unwrap();
        fs::create_dir_all(root.join(CLASSES_DIR)).unwrap();
        root
    }

    /// The record the staged svctest recipe's `env` line carries.
    fn staged_record(root: &Path) -> String
    {
        let recipe = fs::read_to_string(root.join(SERVICES_DIR).join(SVCTEST_RECIPE)).unwrap();
        let prefix = format!("{ENV}=");
        recipe
            .split_whitespace()
            .find_map(|pair| pair.strip_prefix(prefix.as_str()))
            .unwrap()
            .to_owned()
    }

    // Defect caught: a staging that co-stages another set than it records, or
    // keeps a fixture an earlier staging of another set left, so svctest's
    // record and the image disagree.
    #[test]
    fn each_set_stages_exactly_its_fixtures_and_records_them()
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
                let staged = fs::read_to_string(services.join(fixture.recipe())).ok();
                let want = set
                    .fixtures()
                    .contains(&fixture)
                    .then(|| fixture.name().to_owned());
                assert_eq!(staged, want, "{set:?} {fixture:?}");
            }
            let record = staged_record(&root);
            assert_eq!(
                Declared::parse(&record).unwrap(),
                Declared::of(set.fixtures()),
                "{set:?}: {record}"
            );
            assert_eq!(
                fs::read_to_string(root.join(CLASSES_DIR).join("test-dma.class")).unwrap(),
                "dma"
            );
            let recipe = fs::read_to_string(services.join(SVCTEST_RECIPE)).unwrap();
            assert!(
                recipe.starts_with("# svctest\nbinary = /tests/svctest\n")
                    && recipe.ends_with("\nrestart = never\n"),
                "{recipe}"
            );
            fs::remove_dir_all(&root).unwrap();
        }
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
        assert_eq!(
            with_record("binary = /x\nenv = A=1  \n", "memhog").unwrap(),
            "binary = /x\nenv = A=1 SVCTEST_FIXTURES=memhog\n"
        );
        assert_eq!(
            with_record("env = A=1", NONE).unwrap(),
            "env = A=1 SVCTEST_FIXTURES=none"
        );
        for refused in [
            "binary = /x\n",
            "env = A=1\nenv = B=2\n",
            "env = A=1 SVCTEST_FIXTURES=memhog\n",
        ]
        {
            assert!(with_record(refused, "memhog").is_err(), "{refused:?}");
        }
    }

    // Defect caught: a set naming a fixture whose recipe the repository does
    // not ship, or svctest's repository recipe carrying a record of its own,
    // which every staging would refuse.
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
        with_record(&recipe, NONE).unwrap();
    }
}
