// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/usertest/src/lib.rs

//! Host-testable part of the programs-surface test orchestrator: the
//! declaration of which of usertest's recipe seeds each tester takes
//! (docs/testing.md § Per-program tester protocol, Seeds).
//!
//! usertest's recipe seeds the authorities its testers need and declares, in
//! the env entry `TESTER_SEEDS`, which tester takes which:
//! `<tester>:<slot>[,<slot>...]`, one entry per tester, entries joined by
//! `;`. A slot indexes usertest's own seed list; the tester's bootstrap slot
//! `k` is the `k`-th slot its entry names.

/// The env entry that carries the declaration.
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
}

#[cfg(test)]
mod tests
{
    use super::*;

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
