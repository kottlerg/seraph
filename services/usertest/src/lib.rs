// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/usertest/src/lib.rs

//! Host-testable part of the programs-surface test orchestrator: the
//! declarations of its recipe's env and the supervision of one tester's run
//! (docs/testing.md § Per-program tester protocol).
//!
//! The recipe names the testers the image holds in the env entry
//! `TESTERS` ([`TesterList`]), and bounds each tester's run in
//! `TESTER_BOUND_MS` ([`parse_bound`], [`supervise`]).
//!
//! usertest's recipe seeds the authorities its testers need and declares, in
//! the env entry `TESTER_SEEDS`, which tester takes which:
//! `<tester>:<slot>[,<slot>...]`, one entry per tester, entries joined by
//! `;`. A slot indexes usertest's own seed list; the tester's bootstrap slot
//! `k` is the `k`-th slot its entry names.

use std::time::Duration;

/// The env entry that carries the seed declaration.
pub const TESTER_SEEDS: &str = "TESTER_SEEDS";

/// usertest's own seed slot: `pwrmgr.shutdown`, which ends the run and which
/// no tester may take.
pub const OWN_SLOT: usize = 0;

/// Why a declaration was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SeedsError
{
    /// An entry without the `:` between the tester and its slots, or with
    /// an empty tester name.
    Entry(String),
    /// A slot that is not a decimal number, is usertest's own
    /// ([`OWN_SLOT`]), or lies at or past the seed slots usertest takes.
    Slot(String),
    /// A tester named by two entries.
    Repeated(String),
}

/// The parsed declaration: each tester's slots, in the order its bootstrap
/// slots take them.
#[derive(Debug, Default)]
pub struct SeedPlan
{
    entries: Vec<(String, Vec<usize>)>,
}

impl SeedPlan
{
    /// Parse `decl`, the value of [`TESTER_SEEDS`], against usertest's
    /// `slot_count` seed slots. An empty value declares nothing.
    ///
    /// # Errors
    /// The first entry or slot that does not hold, as [`SeedsError`] says.
    pub fn parse(decl: &str, slot_count: usize) -> Result<SeedPlan, SeedsError>
    {
        let mut plan = SeedPlan::default();
        for entry in decl.split(';').filter(|e| !e.is_empty())
        {
            let (tester, slots) = entry
                .split_once(':')
                .filter(|(tester, _)| !tester.is_empty())
                .ok_or_else(|| SeedsError::Entry(entry.to_string()))?;
            if plan.entries.iter().any(|(t, _)| t == tester)
            {
                return Err(SeedsError::Repeated(tester.to_string()));
            }
            let slots = slots
                .split(',')
                .map(|s| match s.parse::<usize>()
                {
                    Ok(slot) if slot != OWN_SLOT && slot < slot_count => Ok(slot),
                    _ => Err(SeedsError::Slot(s.to_string())),
                })
                .collect::<Result<Vec<_>, _>>()?;
            plan.entries.push((tester.to_string(), slots));
        }
        Ok(plan)
    }

    /// The slots declared for `tester`, empty when it has no entry.
    #[must_use]
    pub fn slots_for(&self, tester: &str) -> &[usize]
    {
        self.entries
            .iter()
            .find(|(t, _)| t == tester)
            .map_or(&[], |(_, slots)| slots.as_slice())
    }

    /// The testers the declaration has an entry for.
    pub fn testers(&self) -> impl Iterator<Item = &str>
    {
        self.entries.iter().map(|(t, _)| t.as_str())
    }
}

/// The env entry that names the testers the image holds.
pub const TESTERS: &str = "TESTERS";

/// The env entry that bounds each tester's run, in milliseconds.
pub const TESTER_BOUND_MS: &str = "TESTER_BOUND_MS";

/// Why a [`TESTERS`] list was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TestersError
{
    /// The list names no tester: a run of none would pass having tested nothing.
    Empty,
    /// A tester named twice.
    Repeated(String),
}

/// The testers usertest's recipe names under [`TESTERS`], `<tester>;<tester>...`: the set the
/// testers directory must hold, no more and no fewer.
#[derive(Debug)]
pub struct TesterList
{
    names: Vec<String>,
}

/// A difference between the named testers and those the testers directory holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mismatch
{
    /// Named in [`TESTERS`], absent from the directory.
    Missing(String),
    /// In the directory, not named in [`TESTERS`].
    Unnamed(String),
}

/// The testers to run, in the order the directory gave them, and every [`Mismatch`].
#[derive(Debug, PartialEq, Eq)]
pub struct Reconciled
{
    /// The named testers the directory holds.
    pub run: Vec<String>,
    /// The named testers it lacks, then the testers it holds unnamed.
    pub mismatches: Vec<Mismatch>,
}

impl TesterList
{
    /// Parse `decl`, the value of [`TESTERS`]. Empty entries are skipped.
    ///
    /// # Errors
    /// [`TestersError::Empty`] for a list of no tester, [`TestersError::Repeated`] for a tester
    /// named twice.
    pub fn parse(decl: &str) -> Result<TesterList, TestersError>
    {
        let mut names: Vec<String> = Vec::new();
        for name in decl.split(';').filter(|n| !n.is_empty())
        {
            if names.iter().any(|n| n == name)
            {
                return Err(TestersError::Repeated(name.to_string()));
            }
            names.push(name.to_string());
        }
        if names.is_empty()
        {
            return Err(TestersError::Empty);
        }
        Ok(TesterList { names })
    }

    /// The first tester `plan` declares seeds for that this list does not name: a declaration
    /// for a tester that never runs.
    #[must_use]
    pub fn unlisted_seed_entry<'a>(&self, plan: &'a SeedPlan) -> Option<&'a str>
    {
        plan.testers().find(|t| !self.names.iter().any(|n| n == t))
    }

    /// Compare the list with `found`, the testers the directory holds: the named ones present
    /// run, in `found`'s order, and each named one absent and each present one unnamed is a
    /// [`Mismatch`].
    #[must_use]
    pub fn reconcile(&self, found: &[String]) -> Reconciled
    {
        let named = |f: &String| self.names.contains(f);
        let run = found.iter().filter(|f| named(f)).cloned().collect();
        let mismatches = self
            .names
            .iter()
            .filter(|n| !found.contains(n))
            .map(|n| Mismatch::Missing(n.clone()))
            .chain(
                found
                    .iter()
                    .filter(|f| !named(f))
                    .map(|f| Mismatch::Unnamed(f.clone())),
            )
            .collect();
        Reconciled { run, mismatches }
    }
}

/// Parse `value`, the value of [`TESTER_BOUND_MS`]: a decimal count of milliseconds above zero.
/// `None` for any other value, which bounds no run.
#[must_use]
pub fn parse_bound(value: &str) -> Option<Duration>
{
    match value.parse::<u64>()
    {
        Ok(ms) if ms > 0 => Some(Duration::from_millis(ms)),
        _ => None,
    }
}

/// One tester's run as [`supervise`] drives it: the process, the readers of its two output
/// streams, and the clock.
pub trait Supervised
{
    /// The tester's exit status.
    type Status: Copy;

    /// The exit status once the tester has ended, `None` while it runs.
    ///
    /// # Errors
    /// The wait failed; the tester's state is unknown.
    fn try_wait(&mut self) -> Result<Option<Self::Status>, String>;

    /// Whether both output streams have reached their end and their readers are done.
    fn streams_closed(&self) -> bool;

    /// Stop the tester.
    ///
    /// # Errors
    /// The stop failed, and the tester may still run.
    fn kill(&mut self) -> Result<(), String>;

    /// The time since the tester started.
    fn elapsed(&self) -> Duration;

    /// Wait one poll interval.
    fn pause(&mut self);
}

/// How a supervised run ended.
#[derive(Debug, PartialEq, Eq)]
pub enum RunEnd<S>
{
    /// The tester exited with this status, and its streams closed, within the bound.
    Finished(S),
    /// The bound passed first.
    Overran(Overrun),
}

/// What [`supervise`] saw of a run the bound cut short.
#[derive(Debug, PartialEq, Eq)]
pub struct Overrun
{
    /// The tester had exited within the bound and only its output was still open, so nothing
    /// was killed.
    pub exited_in_bound: bool,
    /// The error of a kill that failed.
    pub kill_error: Option<String>,
    /// The tester's exit was seen by the end of the drain.
    pub reaped: bool,
    /// Both streams were closed by the end of the drain.
    pub streams_closed: bool,
}

impl Overrun
{
    /// The reason of the tester's FAIL line, for a run bounded by `bound`.
    #[must_use]
    pub fn reason(&self, bound: Duration) -> String
    {
        let ms = bound.as_millis();
        let mut reason = if self.exited_in_bound
        {
            format!("exited, output still open at {ms} ms")
        }
        else
        {
            format!("no exit within {ms} ms")
        };
        if let Some(e) = &self.kill_error
        {
            reason.push_str("; kill: ");
            reason.push_str(e);
        }
        else if !self.reaped
        {
            reason.push_str("; no exit after the kill");
        }
        if !self.streams_closed
        {
            reason.push_str("; output still open after the drain");
        }
        reason
    }
}

/// Run `run` to its end or to `bound`, whichever is first. A tester still running at the bound
/// is killed; then, for up to `drain` more, its exit and the close of its streams are awaited,
/// so the caller joins the readers when they are done and leaves them otherwise.
///
/// # Errors
/// A wait failed before the bound: the tester was killed, and the reason names the wait's error
/// and any kill error.
pub fn supervise<R: Supervised>(
    run: &mut R,
    bound: Duration,
    drain: Duration,
) -> Result<RunEnd<R::Status>, String>
{
    let mut status = None;
    while run.elapsed() < bound
    {
        if status.is_none()
        {
            status = match run.try_wait()
            {
                Ok(s) => s,
                Err(e) => return Err(kill_after_failed_wait(run, &e)),
            };
        }
        if let Some(s) = status
            && run.streams_closed()
        {
            return Ok(RunEnd::Finished(s));
        }
        run.pause();
    }
    let exited_in_bound = status.is_some();
    let kill_error = if exited_in_bound
    {
        None
    }
    else
    {
        run.kill().err()
    };
    let end = run.elapsed().saturating_add(drain);
    loop
    {
        if status.is_none()
        {
            status = run.try_wait().ok().flatten();
        }
        let streams_closed = run.streams_closed();
        if (status.is_some() && streams_closed) || run.elapsed() >= end
        {
            return Ok(RunEnd::Overran(Overrun {
                exited_in_bound,
                kill_error,
                reaped: status.is_some(),
                streams_closed,
            }));
        }
        run.pause();
    }
}

/// Kill `run` after its wait failed with `error`, so no tester outlives its verdict, and give
/// the reason of its FAIL line.
fn kill_after_failed_wait<R: Supervised>(run: &mut R, error: &str) -> String
{
    match run.kill()
    {
        Ok(()) => format!("wait: {error}"),
        Err(k) => format!("wait: {error}; kill: {k}"),
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn names(list: &[&str]) -> Vec<String>
    {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    // The defect caught: an empty list, which would let a run of no tester pass, or a tester
    // named twice, which the run would count once.
    #[test]
    fn an_empty_list_and_a_repeated_tester_are_refused()
    {
        assert_eq!(TesterList::parse("").unwrap_err(), TestersError::Empty);
        assert_eq!(TesterList::parse(";;").unwrap_err(), TestersError::Empty);
        assert_eq!(
            TesterList::parse("hello;shell;hello").unwrap_err(),
            TestersError::Repeated("hello".to_string())
        );
    }

    #[test]
    fn the_named_testers_present_run_in_the_directory_order()
    {
        let list = TesterList::parse("shell;hello").unwrap();
        assert_eq!(
            list.reconcile(&names(&["hello", "shell"])),
            Reconciled {
                run: names(&["hello", "shell"]),
                mismatches: Vec::new(),
            }
        );
    }

    // The defect caught: a tester the image lost, or one it holds that nothing names, passing
    // unnoticed; an empty directory among them.
    #[test]
    fn a_missing_named_tester_and_an_unnamed_present_one_are_each_a_mismatch()
    {
        let list = TesterList::parse("hello;shell;stdiotest").unwrap();
        assert_eq!(
            list.reconcile(&names(&["extra", "hello", "stdiotest"])),
            Reconciled {
                run: names(&["hello", "stdiotest"]),
                mismatches: vec![
                    Mismatch::Missing("shell".to_string()),
                    Mismatch::Unnamed("extra".to_string()),
                ],
            }
        );
        assert_eq!(
            list.reconcile(&[]).mismatches,
            vec![
                Mismatch::Missing("hello".to_string()),
                Mismatch::Missing("shell".to_string()),
                Mismatch::Missing("stdiotest".to_string()),
            ]
        );
    }

    #[test]
    fn a_seed_entry_for_a_tester_the_list_does_not_name_is_found()
    {
        let plan = SeedPlan::parse("hello:1;crashme:2", 4).unwrap();
        assert_eq!(
            TesterList::parse("hello")
                .unwrap()
                .unlisted_seed_entry(&plan),
            Some("crashme")
        );
        assert_eq!(
            TesterList::parse("crashme;hello")
                .unwrap()
                .unlisted_seed_entry(&plan),
            None
        );
    }

    #[test]
    fn the_bound_is_a_positive_count_of_milliseconds()
    {
        assert_eq!(parse_bound("120000"), Some(Duration::from_secs(120)));
        for refused in ["", "0", "-5", "2s", "1.5"]
        {
            assert_eq!(parse_bound(refused), None, "{refused:?}");
        }
    }

    /// A tester run on a clock that each pause advances by [`Fake::STEP`]: it exits at
    /// `exit_at` (never when `None`), or at a kill when `dies_on_kill`; its streams close at
    /// `close_at`, or at its death by a kill when `closes_on_kill`.
    struct Fake
    {
        now: Duration,
        exit_at: Option<Duration>,
        close_at: Option<Duration>,
        dies_on_kill: bool,
        closes_on_kill: bool,
        wait_fails: bool,
        killed_at: Option<Duration>,
    }

    impl Fake
    {
        const STEP: Duration = Duration::from_millis(20);

        fn new(exit_at: Option<u64>, close_at: Option<u64>) -> Fake
        {
            Fake {
                now: Duration::ZERO,
                exit_at: exit_at.map(Duration::from_millis),
                close_at: close_at.map(Duration::from_millis),
                dies_on_kill: true,
                closes_on_kill: true,
                wait_fails: false,
                killed_at: None,
            }
        }
    }

    impl Supervised for Fake
    {
        type Status = i32;

        fn try_wait(&mut self) -> Result<Option<i32>, String>
        {
            if self.wait_fails
            {
                return Err("refused".to_string());
            }
            Ok(self.exit_at.filter(|&t| t <= self.now).map(|_| 0))
        }

        fn streams_closed(&self) -> bool
        {
            self.close_at.is_some_and(|t| t <= self.now)
        }

        fn kill(&mut self) -> Result<(), String>
        {
            self.killed_at = Some(self.now);
            if !self.dies_on_kill
            {
                return Err("denied".to_string());
            }
            self.exit_at = Some(self.now);
            if self.closes_on_kill
            {
                self.close_at = Some(self.now);
            }
            Ok(())
        }

        fn elapsed(&self) -> Duration
        {
            self.now
        }

        fn pause(&mut self)
        {
            self.now += Fake::STEP;
        }
    }

    const BOUND: Duration = Duration::from_millis(1000);
    const DRAIN: Duration = Duration::from_millis(200);

    #[test]
    fn a_tester_that_exits_within_the_bound_finishes_with_its_status_unkilled()
    {
        let mut run = Fake::new(Some(400), Some(420));
        assert_eq!(supervise(&mut run, BOUND, DRAIN), Ok(RunEnd::Finished(0)));
        assert_eq!(run.killed_at, None);
    }

    // The defect caught: a hung tester holding the run, or one killed before its bound.
    #[test]
    fn a_tester_still_running_at_the_bound_is_killed_there_and_reported()
    {
        let mut run = Fake::new(None, None);
        let end = supervise(&mut run, BOUND, DRAIN).unwrap();
        assert_eq!(run.killed_at, Some(BOUND));
        let RunEnd::Overran(overrun) = end
        else
        {
            panic!("finished: {end:?}");
        };
        assert_eq!(overrun.reason(BOUND), "no exit within 1000 ms");
    }

    // The defect caught: a tester whose output a process it started holds open, after its own
    // exit, holding the run; nothing is left to kill.
    #[test]
    fn output_open_past_the_bound_after_an_exit_ends_the_run_without_a_kill()
    {
        let mut run = Fake::new(Some(400), None);
        let RunEnd::Overran(overrun) = supervise(&mut run, BOUND, DRAIN).unwrap()
        else
        {
            panic!("finished");
        };
        assert_eq!(run.killed_at, None);
        assert_eq!(run.now, BOUND + DRAIN);
        assert_eq!(
            overrun.reason(BOUND),
            "exited, output still open at 1000 ms; output still open after the drain"
        );
    }

    // The defect caught: a killed tester whose output stays open holding the run past the
    // drain.
    #[test]
    fn a_killed_tester_whose_output_stays_open_ends_the_run_at_the_drain()
    {
        let mut run = Fake::new(None, None);
        run.closes_on_kill = false;
        let RunEnd::Overran(overrun) = supervise(&mut run, BOUND, DRAIN).unwrap()
        else
        {
            panic!("finished");
        };
        assert_eq!(run.now, BOUND + DRAIN);
        assert_eq!(
            overrun.reason(BOUND),
            "no exit within 1000 ms; output still open after the drain"
        );
    }

    #[test]
    fn a_kill_that_fails_is_reported()
    {
        let mut run = Fake::new(None, None);
        run.dies_on_kill = false;
        let RunEnd::Overran(overrun) = supervise(&mut run, BOUND, DRAIN).unwrap()
        else
        {
            panic!("finished");
        };
        assert_eq!(
            overrun.reason(BOUND),
            "no exit within 1000 ms; kill: denied; output still open after the drain"
        );
    }

    // The defect caught: a tester left running after the wait on it failed.
    #[test]
    fn a_failed_wait_kills_the_tester()
    {
        let mut run = Fake::new(None, None);
        run.wait_fails = true;
        assert_eq!(
            supervise(&mut run, BOUND, DRAIN),
            Err("wait: refused".to_string())
        );
        assert_eq!(run.killed_at, Some(Duration::ZERO));
    }

    #[test]
    fn each_tester_takes_the_slots_its_entry_names_in_order()
    {
        let plan = SeedPlan::parse("hello:1;crashme:3,2", 4).unwrap();
        assert_eq!(plan.slots_for("hello"), &[1]);
        assert_eq!(plan.slots_for("crashme"), &[3, 2]);
    }

    #[test]
    fn a_tester_without_an_entry_and_an_empty_declaration_take_nothing()
    {
        let plan = SeedPlan::parse("hello:1", 4).unwrap();
        assert_eq!(plan.slots_for("deadline"), &[] as &[usize]);
        assert_eq!(
            SeedPlan::parse("", 4).unwrap().slots_for("hello"),
            &[] as &[usize]
        );
    }

    // The defect caught: a tester handed usertest's own shutdown authority,
    // or a slot usertest never took, which would reach the tester as an
    // absent cap instead of failing the run.
    #[test]
    fn the_own_slot_and_a_slot_past_the_seeds_are_refused()
    {
        assert_eq!(
            SeedPlan::parse("hello:0", 4).unwrap_err(),
            SeedsError::Slot("0".to_string())
        );
        assert_eq!(
            SeedPlan::parse("hello:4", 4).unwrap_err(),
            SeedsError::Slot("4".to_string())
        );
    }

    #[test]
    fn malformed_entries_and_repeated_testers_are_refused()
    {
        assert_eq!(
            SeedPlan::parse("hello", 4).unwrap_err(),
            SeedsError::Entry("hello".to_string())
        );
        assert_eq!(
            SeedPlan::parse(":1", 4).unwrap_err(),
            SeedsError::Entry(":1".to_string())
        );
        assert_eq!(
            SeedPlan::parse("hello:x", 4).unwrap_err(),
            SeedsError::Slot("x".to_string())
        );
        assert_eq!(
            SeedPlan::parse("hello:", 4).unwrap_err(),
            SeedsError::Slot(String::new())
        );
        assert_eq!(
            SeedPlan::parse("hello:1;hello:2", 4).unwrap_err(),
            SeedsError::Repeated("hello".to_string())
        );
    }
}
