// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/bounded_wait.rs

//! Clock-bounded busy waits with a spin-count fallback.
//!
//! A kernel spin on a hardware or cross-CPU condition is bounded in time, not in loop
//! iterations, because an iteration's cost depends on the CPU and on the device (see
//! docs/limits.md § Cross-Cutting Findings, spin-count timeouts). The clock is whatever
//! the caller passes: microseconds from `timer::elapsed_us` for the IPI waits, the frame
//! allocator and tag-pool lock waits, the tag eviction retry, and the boot's wait for each
//! AP to come online; raw TSC ticks for the x86-64 PIT calibration poll. When the clock
//! gives no reading (the timer is not yet calibrated), the elapsed time is estimated from
//! the spin count at
//! [`MAX_SPINS_PER_UNIT`]. That estimate is never larger than the true time on any
//! plausible CPU, so the fallback can wait longer than the budget but never times out
//! early.

/// Upper bound on spin iterations per clock unit, used to estimate elapsed time when the
/// clock gives no reading. One iteration is at least one cycle, and 10 000 cycles per
/// microsecond is a 10 GHz clock, above any shipping CPU, so `spins / MAX_SPINS_PER_UNIT`
/// never overstates elapsed microseconds. The fallback is used only by microsecond clocks:
/// the TSC-tick clock of the PIT poll always reads.
pub const MAX_SPINS_PER_UNIT: u64 = 10_000;

/// Time, in microseconds, a kernel spin on a lock or a cross-CPU condition that
/// another CPU releases within microseconds may last before the waiter declares a
/// deadlock and halts. Matches the never-acked step of the IPI ack ladder: a
/// healthy holder, even one whose host core the hypervisor deschedules, releases
/// far sooner, so reaching the budget means the holder will never release. It
/// bounds no capacity.
pub const DEADLOCK_BUDGET_US: u64 = 5_000_000;

/// Elapsed-time tracker for one bounded wait.
///
/// [`WaitTimer::start`] records the clock at the start of the wait. Each
/// [`WaitTimer::elapsed`] call counts one spin and returns the time since the start: the
/// clock delta when both the start and the current reading exist, else the spin-count
/// estimate. A wait that started without a reading stays on the estimate even if the
/// clock starts reading later, since a delta from a missing start would measure time
/// since boot, not since the wait began.
pub struct WaitTimer
{
    start: Option<u64>,
    spins: u64,
}

impl WaitTimer
{
    /// Begin a wait at clock reading `now` (`None` when the clock gives no reading).
    #[must_use]
    pub const fn start(now: Option<u64>) -> Self
    {
        Self {
            start: now,
            spins: 0,
        }
    }

    /// Count one spin and return the elapsed clock units since [`WaitTimer::start`],
    /// given the current reading `now`.
    pub fn elapsed(&mut self, now: Option<u64>) -> u64
    {
        self.spins = self.spins.saturating_add(1);
        match (self.start, now)
        {
            (Some(start), Some(now)) => now.saturating_sub(start),
            _ => self.spins / MAX_SPINS_PER_UNIT,
        }
    }
}

/// Spin until `cond` holds or `budget` clock units elapse; return whether `cond` held.
///
/// `now` reads the clock (`None` when it gives no reading; see the module doc for the
/// fallback). `cond` is evaluated before each elapsed-time check, so a condition that
/// already holds returns `true` without spinning.
pub fn spin_until(
    mut cond: impl FnMut() -> bool,
    mut now: impl FnMut() -> Option<u64>,
    budget: u64,
) -> bool
{
    let mut timer = WaitTimer::start(now());
    loop
    {
        if cond()
        {
            return true;
        }
        if timer.elapsed(now()) >= budget
        {
            return false;
        }
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn condition_that_holds_returns_true_before_the_budget()
    {
        let mut polls = 0;
        let held = spin_until(
            || {
                polls += 1;
                polls == 3
            },
            || Some(0),
            10,
        );
        assert!(held);
        assert_eq!(polls, 3);
    }

    #[test]
    fn clock_past_the_budget_ends_the_wait()
    {
        let mut t = 0u64;
        let held = spin_until(
            || false,
            || {
                t += 4;
                Some(t)
            },
            10,
        );
        assert!(!held);
        // The start reads 4; the wait ends at the first reading at least 10 units later (16).
        assert_eq!(t, 16);
    }

    #[test]
    fn missing_clock_falls_back_to_the_spin_estimate()
    {
        let mut spins = 0u64;
        let held = spin_until(
            || {
                spins += 1;
                false
            },
            || None,
            2,
        );
        assert!(!held);
        assert_eq!(spins, 2 * MAX_SPINS_PER_UNIT);
    }

    #[test]
    fn a_clock_that_appears_mid_wait_is_not_read_as_time_since_the_start()
    {
        // Started without a reading; a later reading of 1e9 (time since boot) must not end a
        // 10-unit wait at once.
        let mut timer = WaitTimer::start(None);
        assert_eq!(timer.elapsed(Some(1_000_000_000)), 0);
    }
}
