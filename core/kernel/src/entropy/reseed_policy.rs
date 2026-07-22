// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/entropy/reseed_policy.rs

//! Per-CPU generator reseed policy.
//!
//! The single decision point for when a generator reseeds and how hard it
//! tries. Pure and host-testable; the per-CPU generator supplies its
//! bookkeeping and acts on the returned [`Action`].
//!
//! Two tiers:
//! - **Mandatory** reseeds block on the pool lock. They are the correctness
//!   tier: a never-seeded generator must not emit output, a VMGENID change
//!   means the whole VM state (pool and generator included) may be a replayed
//!   snapshot, and a generator far past its time budget must not keep
//!   deferring forever under sustained pool-lock contention.
//! - **Opportunistic** reseeds are hygiene: the draw-count interval and the
//!   time budget bound how much output depends on any single seed. They use
//!   the non-spinning pool path and defer one draw when the lock is
//!   contended, so a tight-loop consumer cannot amplify cross-CPU
//!   interrupts-off tail latency on the pool leaf lock.

/// Draws between reseeds. Bounds how much output depends on any single seed
/// without making reseeding (a pool lock + permutations) a per-draw cost.
pub const RESEED_DRAW_INTERVAL: u64 = 256;

/// Time budget between reseeds, in microseconds of guest time. Bounds how
/// long a resumed VM snapshot can keep emitting from replayed generator
/// state on platforms without a VMGENID channel (riscv64).
pub const RESEED_TIME_BUDGET_US: u64 = 1_000_000;

/// Overdue multiplier past which the time budget escalates from an
/// opportunistic reseed to a mandatory one, keeping the budget a hard bound
/// under sustained pool-lock contention.
pub const RESEED_OVERDUE_FACTOR: u64 = 2;

/// What the generator must do before producing output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action
{
    /// Draw from the current state.
    None,
    /// Reseed via the non-spinning pool path; on contention, defer one draw.
    Opportunistic,
    /// Reseed via the blocking pool path before any output.
    Mandatory,
}

/// Decide the reseed action for one draw.
///
/// `now_us` is a monotonic microsecond timestamp, `0` when the timer is not
/// yet calibrated — the time budget then never triggers (draw-count and
/// first-use policy still apply).
pub fn decide(
    seeded: bool,
    guid_changed: bool,
    draws_since_reseed: u64,
    now_us: u64,
    last_reseed_us: u64,
) -> Action
{
    if !seeded || guid_changed
    {
        return Action::Mandatory;
    }

    let elapsed_us = if now_us == 0
    {
        0
    }
    else
    {
        now_us.saturating_sub(last_reseed_us)
    };
    if elapsed_us >= RESEED_TIME_BUDGET_US.saturating_mul(RESEED_OVERDUE_FACTOR)
    {
        return Action::Mandatory;
    }
    if draws_since_reseed >= RESEED_DRAW_INTERVAL || elapsed_us >= RESEED_TIME_BUDGET_US
    {
        return Action::Opportunistic;
    }
    Action::None
}

#[cfg(test)]
mod tests
{
    use super::*;

    const BUDGET: u64 = RESEED_TIME_BUDGET_US;
    const OVERDUE: u64 = RESEED_TIME_BUDGET_US * RESEED_OVERDUE_FACTOR;

    #[test]
    fn unseeded_is_mandatory_regardless_of_other_state()
    {
        assert_eq!(decide(false, false, 0, 0, 0), Action::Mandatory);
        assert_eq!(decide(false, true, 999, 5, 5), Action::Mandatory);
    }

    #[test]
    fn guid_change_is_mandatory_even_when_freshly_reseeded()
    {
        assert_eq!(decide(true, true, 0, 100, 100), Action::Mandatory);
    }

    #[test]
    fn steady_state_draws_from_current_state()
    {
        assert_eq!(decide(true, false, 0, 1_000, 1_000), Action::None);
        assert_eq!(
            decide(true, false, RESEED_DRAW_INTERVAL - 1, 1_000, 1_000),
            Action::None
        );
    }

    #[test]
    fn draw_interval_boundary_is_opportunistic()
    {
        assert_eq!(
            decide(true, false, RESEED_DRAW_INTERVAL, 1_000, 1_000),
            Action::Opportunistic
        );
        assert_eq!(
            decide(true, false, RESEED_DRAW_INTERVAL + 1, 1_000, 1_000),
            Action::Opportunistic
        );
    }

    #[test]
    fn time_budget_boundary_is_opportunistic()
    {
        let last = 500;
        assert_eq!(
            decide(true, false, 0, last + BUDGET - 1, last),
            Action::None
        );
        assert_eq!(
            decide(true, false, 0, last + BUDGET, last),
            Action::Opportunistic
        );
    }

    #[test]
    fn overdue_boundary_escalates_to_mandatory()
    {
        let last = 500;
        assert_eq!(
            decide(true, false, 0, last + OVERDUE - 1, last),
            Action::Opportunistic
        );
        assert_eq!(
            decide(true, false, 0, last + OVERDUE, last),
            Action::Mandatory
        );
    }

    #[test]
    fn uncalibrated_timer_never_triggers_the_budget()
    {
        // now_us == 0 means "no timestamp"; only first-use and the draw
        // interval may fire.
        assert_eq!(decide(true, false, 0, 0, 0), Action::None);
        assert_eq!(
            decide(true, false, RESEED_DRAW_INTERVAL, 0, 0),
            Action::Opportunistic
        );
    }

    #[test]
    fn clock_regression_does_not_underflow()
    {
        // last_reseed_us ahead of now_us (cross-CPU timestamp skew) must not
        // wrap into a huge elapsed value.
        assert_eq!(decide(true, false, 0, 100, 200), Action::None);
    }
}
