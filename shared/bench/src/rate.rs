// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/bench/src/rate.rs

//! The check that a window's cycle count covered all of its elapsed time.
//!
//! A thread reads the cycle counter of the CPU it is pinned to. A window in
//! which that CPU may halt (its reader blocks while other threads do the
//! window's work elsewhere) counts its elapsed time only if the counter runs
//! through a halt, which riscv64 leaves to the implementation (README.md
//! § Window rate check). The reader therefore also reads a clock that runs
//! through halts, the kernel's elapsed microseconds, around each window, and
//! measures the counter's rate against that clock over a span in which the
//! CPU did not halt. A window whose cycles fall short of its elapsed time at
//! that rate, by more than the check's tolerance, did not count all of it.

/// The percentage by which a window's cycles may fall short of its elapsed
/// time at the measured rate: the rate's own error and the elapsed clock's
/// truncation over a long window.
pub const RATE_TOLERANCE_PERCENT: u64 = 5;

/// The percentage of the elapsed time at the rate a window's cycles must reach.
const FLOOR_PERCENT: u64 = 100 - RATE_TOLERANCE_PERCENT;

/// The microseconds of a window's elapsed time the check does not require the
/// cycles to cover: the truncation of each of the two elapsed reads to a whole
/// microsecond, and the reads themselves, which lie outside the cycle reads.
pub const RATE_SLACK_MICROS: u64 = 3;

/// A cycle counter's rate against the elapsed-time clock: `cycles` over
/// `micros`, measured over a span in which the counter's CPU did not halt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CycleRate
{
    /// Cycles the counter advanced over the measured span.
    cycles: u64,
    /// Microseconds the elapsed clock advanced over the same span.
    micros: u64,
}

impl CycleRate
{
    /// The rate of `cycles` over `micros`, or `None` when either is zero,
    /// which measures no rate.
    #[must_use]
    pub const fn new(cycles: u64, micros: u64) -> Option<Self>
    {
        if cycles == 0 || micros == 0
        {
            return None;
        }
        Some(Self { cycles, micros })
    }

    /// Whether a window of `cycles`, read between two reads of the elapsed
    /// clock `micros` apart, counted its elapsed time: `false` when the cycles
    /// fall short of `micros`, less [`RATE_SLACK_MICROS`], at this rate by
    /// more than [`RATE_TOLERANCE_PERCENT`], as a counter that stopped while
    /// its CPU halted leaves them.
    #[must_use]
    pub fn counted(&self, cycles: u64, micros: u64) -> bool
    {
        let covered = u128::from(micros.saturating_sub(RATE_SLACK_MICROS));
        // A product of two u64 values fits a u128, and `new` refused a zero
        // divisor; the floor's product saturates only above every u64 count.
        let expected = covered
            .saturating_mul(u128::from(self.cycles))
            .checked_div(u128::from(self.micros))
            .unwrap_or(0);
        let floor = expected.saturating_mul(u128::from(FLOOR_PERCENT)) / 100;
        u128::from(cycles) >= floor
    }
}

#[cfg(test)]
mod tests
{
    use super::{CycleRate, RATE_SLACK_MICROS};

    #[test]
    fn a_rate_needs_cycles_and_micros()
    {
        assert_eq!(CycleRate::new(0, 10), None);
        assert_eq!(CycleRate::new(10, 0), None);
    }

    #[test]
    fn a_window_at_the_rate_counts_and_one_whose_counter_stopped_for_half_does_not()
    {
        // 1000 cycles per microsecond.
        let rate = CycleRate::new(2_000_000, 2_000).unwrap();
        assert!(rate.counted(100_000, 100));
        // Short by the tolerance and the slack: still counted.
        assert!(rate.counted(92_200, 100));
        // The counter stopped for half the window.
        assert!(!rate.counted(50_000, 100));
        // Just under the floor: (100 - 3) * 1000 * 95 / 100 = 92_150.
        assert!(!rate.counted(92_149, 100));
        assert!(rate.counted(92_150, 100));
    }

    #[test]
    fn a_window_within_the_slack_always_counts()
    {
        let rate = CycleRate::new(1_000, 1).unwrap();
        assert!(rate.counted(0, RATE_SLACK_MICROS));
        assert!(!rate.counted(0, RATE_SLACK_MICROS + 1));
    }

    #[test]
    fn the_largest_values_do_not_overflow()
    {
        let rate = CycleRate::new(u64::MAX, 1).unwrap();
        assert!(!rate.counted(u64::MAX, u64::MAX));
        assert!(rate.counted(u64::MAX, RATE_SLACK_MICROS + 1));
    }
}
