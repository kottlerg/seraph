// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/testkit/src/differential.rs

//! The differential driver: run each case through the implementation under
//! test and through a reference, and record every case where they disagree.
//!
//! The driver is generic over the input and the outcome. A caller states the
//! outcome both sides are mapped to (a verdict, a digest), so the comparison
//! is exact: an outcome type finer than accept or reject (which check failed)
//! makes the harness check that too. Every disagreement is kept, with its
//! input, so one run reports them all.

use std::fmt;

/// One case on which the two sides disagreed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disagreement
{
    /// The case, as its `Debug` form prints it.
    pub case: String,
    /// The implementation under test's outcome.
    pub ours: String,
    /// The reference's outcome.
    pub reference: String,
}

/// The result of one differential run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report
{
    /// What was compared, for the failure message.
    pub name: String,
    /// The number of cases run.
    pub cases: usize,
    /// Every case on which the sides disagreed, in run order.
    pub disagreements: Vec<Disagreement>,
}

/// How many disagreements a report prints in full.
const PRINTED: usize = 16;

impl Report
{
    /// Whether the sides agreed on every case, and at least one case ran: a
    /// run of no cases compares nothing.
    #[must_use]
    pub fn agrees(&self) -> bool
    {
        self.cases > 0 && self.disagreements.is_empty()
    }
}

impl fmt::Display for Report
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        writeln!(
            f,
            "{}: {} of {} cases disagree",
            self.name,
            self.disagreements.len(),
            self.cases
        )?;
        for d in self.disagreements.iter().take(PRINTED)
        {
            writeln!(f, "  case {}", d.case)?;
            writeln!(f, "    ours:      {}", d.ours)?;
            writeln!(f, "    reference: {}", d.reference)?;
        }
        if self.disagreements.len() > PRINTED
        {
            writeln!(
                f,
                "  ... and {} more",
                self.disagreements.len().wrapping_sub(PRINTED)
            )?;
        }
        Ok(())
    }
}

/// Run every case of `cases` through `ours` and `reference`, and report each
/// case whose outcomes differ.
pub fn compare<I, O>(
    name: &str,
    cases: impl IntoIterator<Item = I>,
    mut ours: impl FnMut(&I) -> O,
    mut reference: impl FnMut(&I) -> O,
) -> Report
where
    I: fmt::Debug,
    O: PartialEq + fmt::Debug,
{
    let mut report = Report {
        name: name.to_owned(),
        cases: 0,
        disagreements: Vec::new(),
    };
    for case in cases
    {
        report.cases = report.cases.wrapping_add(1);
        let got = ours(&case);
        let want = reference(&case);
        if got != want
        {
            report.disagreements.push(Disagreement {
                case: format!("{case:?}"),
                ours: format!("{got:?}"),
                reference: format!("{want:?}"),
            });
        }
    }
    report
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn compare_records_every_disagreeing_case_with_both_outcomes()
    {
        let report = compare(
            "parity",
            0u32..6,
            |n| n % 2,
            |n| if *n == 3 { 0 } else { n % 2 },
        );
        assert_eq!(report.cases, 6);
        assert_eq!(
            report.disagreements,
            [Disagreement {
                case: "3".into(),
                ours: "1".into(),
                reference: "0".into(),
            }]
        );
        assert!(!report.agrees());
        assert!(report.to_string().contains("1 of 6 cases disagree"));
    }

    #[test]
    fn a_run_of_no_cases_does_not_agree()
    {
        let report = compare("empty", Vec::<u8>::new(), |_| 0, |_| 0);
        assert!(!report.agrees());
    }
}
