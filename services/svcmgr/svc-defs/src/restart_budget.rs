// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/svc-defs/src/restart_budget.rs

//! svcmgr's windowed restart budget: how many restarts a service may run
//! before a death leaves it permanently down.
//!
//! A service may restart [`RESTART_BURST`] times within one
//! [`RESTART_WINDOW_NS`] window. The window opens at the first restart after
//! the previous window has passed, so a service that crashes rarely restarts
//! every time, however long the boot, while one that crash-loops is stopped
//! after a burst. The policy is specified in
//! `services/svcmgr/docs/restart-protocol.md` § Decision tree.

/// Restarts a service may run within one [`RESTART_WINDOW_NS`] window.
pub const RESTART_BURST: u32 = 3;

/// Length of a restart window, in nanoseconds of monotonic time: 60 s.
pub const RESTART_WINDOW_NS: u64 = 60_000_000_000;

/// One service's restart budget.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RestartBudget
{
    /// Monotonic time the current window opened at; `None` before the first
    /// restart.
    window_start_ns: Option<u64>,
    /// Restarts charged to the current window.
    used: u32,
}

impl RestartBudget
{
    /// A budget with no restart charged.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            window_start_ns: None,
            used: 0,
        }
    }

    /// Charge one restart at monotonic time `now_ns`, opening a fresh window
    /// when none is open or the open one has passed. Returns `false`, and
    /// charges nothing, when the open window's [`RESTART_BURST`] restarts are
    /// spent.
    pub fn try_charge(&mut self, now_ns: u64) -> bool
    {
        let window_open = self
            .window_start_ns
            .is_some_and(|start| now_ns.saturating_sub(start) < RESTART_WINDOW_NS);
        if !window_open
        {
            self.window_start_ns = Some(now_ns);
            self.used = 0;
        }
        if self.used >= RESTART_BURST
        {
            return false;
        }
        self.used += 1;
        true
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn a_crash_loop_is_stopped_after_one_burst_within_the_window()
    {
        let mut budget = RestartBudget::new();
        for i in 0..u64::from(RESTART_BURST)
        {
            assert!(budget.try_charge(i));
        }
        assert!(!budget.try_charge(u64::from(RESTART_BURST)));
        // A refused charge spends nothing: still refused inside the window.
        assert!(!budget.try_charge(RESTART_WINDOW_NS - 1));
    }

    #[test]
    fn the_budget_refills_once_the_window_has_passed()
    {
        let mut budget = RestartBudget::new();
        for _ in 0..RESTART_BURST
        {
            assert!(budget.try_charge(10));
        }
        assert!(!budget.try_charge(10 + RESTART_WINDOW_NS - 1));
        assert!(budget.try_charge(10 + RESTART_WINDOW_NS));
    }

    #[test]
    fn rare_crashes_restart_every_time_however_many_there_are()
    {
        // One crash per window, far past any lifetime count.
        let mut budget = RestartBudget::new();
        for i in 0..1000u64
        {
            assert!(budget.try_charge(i * RESTART_WINDOW_NS));
        }
    }
}
