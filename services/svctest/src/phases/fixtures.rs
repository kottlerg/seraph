// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/fixtures.rs

//! The fixtures this boot stages (docs/testing.md § Gating). The staging
//! (`cargo xtask mkdisk --svctest <set>`) writes the set it co-staged into
//! svctest's recipe as `SVCTEST_FIXTURES` (`svctest_fixtures`). The
//! `svctest_fixtures` phase, right after the startup phases, reads that
//! record and fails the run unless the image stages exactly the fixtures it
//! declares, and the recipes of the default services svctest's phases drive
//! (oomd and sessiond), naming each recipe that disagrees. A phase whose
//! fixture the record does not declare then skips, or skips the part the
//! fixture drives, and logs `phase=<phase> skipped: <recipe> not staged`
//! ([`skip`]); a declared fixture's phase runs.
//!
//! The phase also requires crashd staged exactly when the run makes every
//! phase: a run whose recipe selects phases (`SVCTEST_PHASES`, the
//! `crash-endpoint` set) needs procmgr's crash endpoint free, and every other
//! run's crashd phases need crashd's svctest recipe (`super::all` applies
//! the selection).

use std::sync::OnceLock;

use svctest_fixtures::{CRASHD_STAGED_PATH, Declared, ENV, Fixture, PHASES_ENV, crashd_staged};

use crate::bootstrap::Caps;
use crate::runner::Phase;

/// The record's declaration, set by [`fixtures_phase`].
static DECLARED: OnceLock<Declared> = OnceLock::new();

/// The recipes of the default services svctest's phases drive, which every
/// svctest boot stages: the `oom_policy` phase reads oomd's policy and has
/// it stop, and the `sessiond_operator` and `oom_policy` phases open
/// sessions.
const DEFAULT_SERVICES: [&str; 2] = [super::oom::OOMD_RECIPE, super::svcmgr::SESSIOND_RECIPE];

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "svctest_fixtures",
        run: fixtures_phase,
    }]
}

/// Read the record and require the image to stage exactly the fixtures it
/// declares, and the default services of [`DEFAULT_SERVICES`].
fn fixtures_phase(_caps: &Caps)
{
    let phase = "svctest_fixtures";
    let record = std::env::var(ENV).unwrap_or_else(|_| {
        panic!(
            "{phase}: no {ENV} in svctest's environment: stage svctest with \
             `cargo xtask mkdisk --svctest <set>` (docs/testing.md § Gating)"
        )
    });
    let declared = Declared::parse(&record)
        .unwrap_or_else(|e| panic!("{phase}: {ENV}={record:?} is refused: {e}"));
    let mut disagree: usize = 0;
    for found in declared.mismatches(|f| super::svcmgr::recipe_staged(f.staged_path(), phase))
    {
        std::os::seraph::log!("{phase}: {found}");
        disagree = disagree.saturating_add(1);
    }
    for recipe in DEFAULT_SERVICES
    {
        if !super::svcmgr::recipe_staged(recipe, phase)
        {
            std::os::seraph::log!("{phase}: {recipe} is not staged: svctest drives that service");
            disagree = disagree.saturating_add(1);
        }
    }
    let selection = std::env::var(PHASES_ENV).ok();
    let want_crashd = crashd_staged(selection.as_deref());
    match (
        want_crashd,
        super::svcmgr::recipe_staged(CRASHD_STAGED_PATH, phase),
    )
    {
        (true, false) =>
        {
            std::os::seraph::log!(
                "{phase}: {CRASHD_STAGED_PATH} is not staged: the crashd phases need crashd's \
                 svctest recipe"
            );
            disagree = disagree.saturating_add(1);
        }
        (false, true) =>
        {
            std::os::seraph::log!(
                "{phase}: {CRASHD_STAGED_PATH} is staged: the run of {PHASES_ENV}={} needs \
                 procmgr's crash endpoint free",
                selection.as_deref().unwrap_or_default()
            );
            disagree = disagree.saturating_add(1);
        }
        (true, true) | (false, false) =>
        {}
    }
    assert_eq!(
        disagree, 0,
        "{phase}: the image disagrees with {ENV}={record} on {disagree} recipes (lines above)"
    );
    let _ = DECLARED.set(declared);
    std::os::seraph::log!("{phase}: {ENV}={record}: the image stages exactly these fixtures");
}

/// Whether the staged set declares `fixture`, and so whether its recipe is
/// staged: [`fixtures_phase`] has failed the run otherwise.
///
/// # Panics
///
/// When called before [`fixtures_phase`] has run, which the phase order
/// rules out (`super::all`).
pub(crate) fn staged(fixture: Fixture) -> bool
{
    DECLARED
        .get()
        .expect("the svctest_fixtures phase reads the record before any phase consults it")
        .contains(fixture)
}

/// Log that `phase`, or the part of it `fixture` drives, skipped, since the
/// staged set does not declare `fixture`.
pub(crate) fn skip(phase: &str, fixture: Fixture)
{
    std::os::seraph::log!("phase={phase} skipped: {} not staged", fixture.recipe());
}
