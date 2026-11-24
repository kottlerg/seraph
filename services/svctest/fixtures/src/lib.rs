// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/fixtures/src/lib.rs

//! The fixtures the svctest boot co-stages, the named sets of them a staging
//! picks, and the record of the staged set that svctest checks the image
//! against (docs/testing.md § Gating).
//!
//! A fixture is a test recipe under `/config/svcmgr/tests/` that one or more
//! svctest phases drive when it is staged into `/config/svcmgr/services/`.
//! `cargo xtask mkdisk --svctest <set>` stages svctest's recipe with the
//! fixtures of one [`Set`] and writes the set into the staged recipe's `env`
//! line as [`ENV`]`=<fixture>,...`, or [`ENV`]`=`[`NONE`] for the empty set.
//! svctest parses that record ([`Declared::parse`]) and refuses a run whose
//! image disagrees with it ([`Declared::mismatches`]): a declared fixture with no staged
//! recipe, or a staged fixture recipe the record does not declare. A phase
//! whose fixture is not declared skips, and logs that it did.
//!
//! Every set but one also stages crashd's svctest recipe
//! ([`CRASHD_RECIPE`]) over the default one, so svctest's crashd phases find
//! a core of each faulting mode of the `crashme` fixture in `/crash`. The
//! `crash-endpoint` set stages no crashd, which leaves procmgr's crash
//! endpoint free for svctest to register as the crash service, and selects
//! the one phase that does: its staging writes [`PHASES_ENV`]`=crash_endpoint`
//! into the recipe, and svctest then runs its startup and fixture-check
//! phases and the phases that record names ([`Set::phases`],
//! [`selects`]). Whether crashd is staged follows from that record
//! ([`crashd_staged`]), which svctest checks the image against too.
//!
//! The crate performs no IPC and issues no syscalls, so it stays host-testable
//! ([coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants)).

#![cfg_attr(not(test), no_std)]

use core::fmt;

/// The `env` key of the staged set's record in svctest's staged recipe.
pub const ENV: &str = "SVCTEST_FIXTURES";

/// The record of the empty set.
pub const NONE: &str = "none";

/// The `env` key of the phase selection in svctest's staged recipe, which
/// a set that runs only some phases writes ([`Set::phases`]).
pub const PHASES_ENV: &str = "SVCTEST_PHASES";

/// The file name of crashd's svctest recipe under `/config/svcmgr/tests/`,
/// staged over crashd's default recipe of the same name.
pub const CRASHD_RECIPE: &str = "crashd.svc";

/// The path svcmgr reads crashd's staged recipe from.
pub const CRASHD_STAGED_PATH: &str = "/config/svcmgr/services/crashd.svc";

/// Whether a run whose recipe carries the phase selection `phases` (the
/// value of [`PHASES_ENV`], `None` when the recipe sets none) has crashd
/// staged: a run of every phase does, the run of a selection does not.
#[must_use]
pub const fn crashd_staged(phases: Option<&str>) -> bool
{
    phases.is_none()
}

/// Whether the phase selection `phases` (a [`PHASES_ENV`] value: phase
/// names separated by commas) names `phase`.
#[must_use]
pub fn selects(phases: &str, phase: &str) -> bool
{
    phases.split(',').any(|name| name == phase)
}

/// A fixture the svctest boot may co-stage. Its recipe is
/// `/config/svcmgr/tests/<name>.svc`, staged as
/// `/config/svcmgr/services/<name>.svc`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fixture
{
    /// `crasher` (`restart = always`), which faults on every spawn and so
    /// drives svcmgr's restart path for the whole run.
    Crasher,
    /// `crasher-worker`, the crasher's worker-fault role, which the
    /// `svcmgr_worker_fault_restart`, `svcmgr_stop_service` and
    /// `critical_creates` phases drive.
    CrasherWorker,
    /// `crasher-boot`, the crasher's boot-fault role, which the
    /// `svcmgr_boot_death` phase drives.
    CrasherBoot,
    /// `memhog`, which the `svcmgr_stop_service`, `oom_policy`,
    /// `rtc_create_retry` and `logd_reserve` phases fill memory with.
    Memhog,
    /// `reserve-creator`, which the `logd_reserve` phase has create from
    /// the reserve while memory is critical.
    ReserveCreator,
    /// `stopsrc`, the stop source of the program class the
    /// `svcmgr_stop_service` and `oom_policy` phases read and stop.
    Stopsrc,
}

impl Fixture
{
    /// Every fixture, in the order a record lists them.
    pub const ALL: [Fixture; 6] = [
        Fixture::Crasher,
        Fixture::CrasherWorker,
        Fixture::CrasherBoot,
        Fixture::Memhog,
        Fixture::ReserveCreator,
        Fixture::Stopsrc,
    ];

    /// The fixture's name: its recipe's file name less `.svc`, and its name
    /// in a record.
    #[must_use]
    pub const fn name(self) -> &'static str
    {
        match self
        {
            Fixture::Crasher => "crasher",
            Fixture::CrasherWorker => "crasher-worker",
            Fixture::CrasherBoot => "crasher-boot",
            Fixture::Memhog => "memhog",
            Fixture::ReserveCreator => "reserve-creator",
            Fixture::Stopsrc => "stopsrc",
        }
    }

    /// The fixture's recipe's file name.
    #[must_use]
    pub const fn recipe(self) -> &'static str
    {
        match self
        {
            Fixture::Crasher => "crasher.svc",
            Fixture::CrasherWorker => "crasher-worker.svc",
            Fixture::CrasherBoot => "crasher-boot.svc",
            Fixture::Memhog => "memhog.svc",
            Fixture::ReserveCreator => "reserve-creator.svc",
            Fixture::Stopsrc => "stopsrc.svc",
        }
    }

    /// The path svcmgr reads the staged recipe from.
    #[must_use]
    pub const fn staged_path(self) -> &'static str
    {
        match self
        {
            Fixture::Crasher => "/config/svcmgr/services/crasher.svc",
            Fixture::CrasherWorker => "/config/svcmgr/services/crasher-worker.svc",
            Fixture::CrasherBoot => "/config/svcmgr/services/crasher-boot.svc",
            Fixture::Memhog => "/config/svcmgr/services/memhog.svc",
            Fixture::ReserveCreator => "/config/svcmgr/services/reserve-creator.svc",
            Fixture::Stopsrc => "/config/svcmgr/services/stopsrc.svc",
        }
    }

    /// The fixture named `name` in a record.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Fixture>
    {
        Fixture::ALL.into_iter().find(|f| f.name() == name)
    }

    /// The fixture's bit in a [`Declared`].
    const fn bit(self) -> u8
    {
        1 << (self as u8)
    }
}

/// A named fixture set: what a staging of the svctest boot co-stages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Set
{
    /// The canonical svctest cells (`build-test.yml`) and the local host
    /// runs that stage svctest as they do: every fixture.
    Ci,
    /// The burn-in svctest cell (`burnin.yml`): no crasher role, so the
    /// repeated boots run no fault fixture; `memhog`, `reserve-creator` and
    /// `stopsrc`.
    BurnIn,
    /// No fixture: every fixture phase skips.
    None,
    /// No fixture and no crashd: the run of procmgr's crash endpoint with
    /// svctest as the crash service, which only a boot without crashd
    /// drives. Its staging selects the `crash_endpoint` phase.
    CrashEndpoint,
}

impl Set
{
    /// Every set.
    pub const ALL: [Set; 4] = [Set::Ci, Set::BurnIn, Set::None, Set::CrashEndpoint];

    /// The set's name, as `mkdisk --svctest` takes it.
    #[must_use]
    pub const fn name(self) -> &'static str
    {
        match self
        {
            Set::Ci => "ci",
            Set::BurnIn => "burn-in",
            Set::None => "none",
            Set::CrashEndpoint => "crash-endpoint",
        }
    }

    /// The set's fixtures, in the order a record lists them.
    #[must_use]
    pub const fn fixtures(self) -> &'static [Fixture]
    {
        match self
        {
            Set::Ci => &Fixture::ALL,
            Set::BurnIn => &[Fixture::Memhog, Fixture::ReserveCreator, Fixture::Stopsrc],
            Set::None | Set::CrashEndpoint => &[],
        }
    }

    /// The phases a run of the set selects, beyond the startup and
    /// fixture-check phases every run makes, as its [`PHASES_ENV`] record
    /// lists them; `None` for a run of every phase.
    #[must_use]
    pub const fn phases(self) -> Option<&'static str>
    {
        match self
        {
            Set::CrashEndpoint => Some("crash_endpoint"),
            Set::Ci | Set::BurnIn | Set::None => None,
        }
    }

    /// Whether a staging of the set stages crashd's svctest recipe.
    #[must_use]
    pub const fn stages_crashd(self) -> bool
    {
        crashd_staged(self.phases())
    }
}

/// The fixtures a record declares staged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Declared(u8);

impl Declared
{
    /// The declaration of exactly `fixtures`.
    #[must_use]
    pub fn of(fixtures: &[Fixture]) -> Declared
    {
        Declared(fixtures.iter().fold(0, |bits, f| bits | f.bit()))
    }

    /// Whether `fixture` is declared staged.
    #[must_use]
    pub const fn contains(self, fixture: Fixture) -> bool
    {
        self.0 & fixture.bit() != 0
    }

    /// The declaration a record states: [`NONE`], or fixture names separated
    /// by commas.
    ///
    /// # Errors
    ///
    /// When the record is empty, names a fixture this crate does not know,
    /// names one twice, or names [`NONE`] beside a fixture.
    pub fn parse(record: &str) -> Result<Declared, ParseError<'_>>
    {
        if record == NONE
        {
            return Ok(Declared(0));
        }
        if record.is_empty()
        {
            return Err(ParseError::Empty);
        }
        let mut declared = Declared(0);
        for name in record.split(',')
        {
            if name == NONE
            {
                return Err(ParseError::NoneBesideFixture);
            }
            let fixture = Fixture::from_name(name).ok_or(ParseError::Unknown(name))?;
            if declared.contains(fixture)
            {
                return Err(ParseError::Repeated(fixture));
            }
            declared.0 |= fixture.bit();
        }
        Ok(declared)
    }
}

/// Why [`Declared::parse`] refused a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError<'a>
{
    /// The record is empty.
    Empty,
    /// The record names no known fixture here.
    Unknown(&'a str),
    /// The record names this fixture twice.
    Repeated(Fixture),
    /// The record names [`NONE`] beside a fixture.
    NoneBesideFixture,
}

impl fmt::Display for ParseError<'_>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self
        {
            ParseError::Empty => write!(f, "the record is empty"),
            ParseError::Unknown(name) => write!(f, "{name:?} is no svctest fixture"),
            ParseError::Repeated(fixture) => write!(f, "{} is named twice", fixture.name()),
            ParseError::NoneBesideFixture => write!(f, "{NONE:?} is named beside a fixture"),
        }
    }
}

/// How the image disagrees with the record about one fixture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mismatch
{
    /// Declared, and its recipe is not staged.
    Missing(Fixture),
    /// Its recipe is staged, and the record does not declare it.
    Undeclared(Fixture),
}

impl fmt::Display for Mismatch
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self
        {
            Mismatch::Missing(fixture) => write!(
                f,
                "fixture {} is in the staged set, and {} is not staged",
                fixture.name(),
                fixture.staged_path()
            ),
            Mismatch::Undeclared(fixture) => write!(
                f,
                "{} is staged, and fixture {} is not in the staged set",
                fixture.staged_path(),
                fixture.name()
            ),
        }
    }
}

impl Declared
{
    /// How the image disagrees with the declaration, fixture by fixture in
    /// [`Fixture::ALL`]'s order, `staged` telling whether a fixture's
    /// recipe is staged; empty when it agrees.
    pub fn mismatches(
        self,
        mut staged: impl FnMut(Fixture) -> bool,
    ) -> impl Iterator<Item = Mismatch>
    {
        Fixture::ALL.into_iter().filter_map(move |fixture| {
            match (self.contains(fixture), staged(fixture))
            {
                (true, false) => Some(Mismatch::Missing(fixture)),
                (false, true) => Some(Mismatch::Undeclared(fixture)),
                _ => None,
            }
        })
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// The record a staging of `set` writes, as xtask writes it.
    fn record(set: Set) -> String
    {
        if set.fixtures().is_empty()
        {
            return NONE.to_owned();
        }
        let names: Vec<&str> = set.fixtures().iter().map(|f| f.name()).collect();
        names.join(",")
    }

    // Defect caught: a set whose record svctest parses as another set, so a
    // phase of a staged fixture skips or one of an unstaged fixture runs.
    #[test]
    fn each_sets_record_declares_exactly_its_fixtures()
    {
        for set in Set::ALL
        {
            let declared = Declared::parse(&record(set)).unwrap();
            assert_eq!(declared, Declared::of(set.fixtures()), "{set:?}");
            for fixture in Fixture::ALL
            {
                assert_eq!(
                    declared.contains(fixture),
                    set.fixtures().contains(&fixture),
                    "{set:?} {fixture:?}"
                );
            }
        }
    }

    // Defect caught: a set whose staging stages crashd while it selects the
    // crash_endpoint phase, so the endpoint is taken and the phase checks only
    // the refusal, or a canonical set that stages none, so the crashd phases
    // find no core; or a selection svctest reads as naming another phase.
    #[test]
    fn only_the_crash_endpoint_set_selects_phases_and_stages_no_crashd()
    {
        for set in Set::ALL
        {
            assert_eq!(set.stages_crashd(), set != Set::CrashEndpoint, "{set:?}");
            assert_eq!(set.phases().is_some(), set == Set::CrashEndpoint, "{set:?}");
        }
        let selection = Set::CrashEndpoint.phases().unwrap();
        assert!(selects(selection, "crash_endpoint"));
        assert!(!selects(selection, "crash"));
        assert!(!selects(selection, "crash_endpoint_x"));
        assert!(selects("a,crash_endpoint", "crash_endpoint"));
        assert!(!crashd_staged(Some(selection)));
        assert!(crashd_staged(None));
        assert_eq!(
            CRASHD_STAGED_PATH,
            format!("/config/svcmgr/services/{CRASHD_RECIPE}")
        );
    }

    // Defect caught: two fixtures sharing a name or a recipe, or a recipe or
    // staged path naming another fixture than its name does.
    #[test]
    fn each_fixture_has_its_own_name_recipe_and_staged_path()
    {
        for fixture in Fixture::ALL
        {
            assert_eq!(Fixture::from_name(fixture.name()), Some(fixture));
            assert_eq!(fixture.recipe(), format!("{}.svc", fixture.name()));
            assert_eq!(
                fixture.staged_path(),
                format!("/config/svcmgr/services/{}", fixture.recipe())
            );
        }
        assert_eq!(Fixture::from_name(NONE), None);
    }

    // Defect caught: a record svctest cannot account for run as if it
    // declared a set, so a mistyped or hand-written record skips phases.
    #[test]
    fn a_record_that_is_no_set_is_refused()
    {
        assert_eq!(Declared::parse(""), Err(ParseError::Empty));
        assert_eq!(Declared::parse("memhog,"), Err(ParseError::Unknown("")));
        assert_eq!(
            Declared::parse("memhogg"),
            Err(ParseError::Unknown("memhogg"))
        );
        assert_eq!(
            Declared::parse("memhog stopsrc"),
            Err(ParseError::Unknown("memhog stopsrc"))
        );
        assert_eq!(
            Declared::parse("memhog,stopsrc,memhog"),
            Err(ParseError::Repeated(Fixture::Memhog))
        );
        assert_eq!(
            Declared::parse("none,memhog"),
            Err(ParseError::NoneBesideFixture)
        );
        assert_eq!(
            Declared::parse("memhog,none"),
            Err(ParseError::NoneBesideFixture)
        );
    }

    // Defect caught: a declared fixture whose recipe is not staged passing as
    // a skip, or a staged fixture the record omits running unaccounted for.
    #[test]
    fn the_image_must_stage_exactly_the_declared_fixtures()
    {
        let declared = Declared::of(&[Fixture::Memhog, Fixture::Stopsrc]);
        let found = |staged: &[Fixture]| -> Vec<Mismatch> {
            declared.mismatches(|f| staged.contains(&f)).collect()
        };
        assert_eq!(found(&[Fixture::Memhog, Fixture::Stopsrc]), []);
        assert_eq!(
            found(&[Fixture::Stopsrc]),
            [Mismatch::Missing(Fixture::Memhog)]
        );
        assert_eq!(
            found(&[Fixture::Crasher, Fixture::Memhog, Fixture::Stopsrc]),
            [Mismatch::Undeclared(Fixture::Crasher)]
        );
        assert_eq!(
            found(&[Fixture::CrasherBoot]),
            [
                Mismatch::Undeclared(Fixture::CrasherBoot),
                Mismatch::Missing(Fixture::Memhog),
                Mismatch::Missing(Fixture::Stopsrc)
            ]
        );
        assert!(
            Mismatch::Missing(Fixture::Memhog)
                .to_string()
                .contains("/config/svcmgr/services/memhog.svc")
        );
    }
}
