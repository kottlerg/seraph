// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/spin-wait/src/lib.rs

//! Contended-wait policy of the seraph std overlay's `SpinMutex`, as pure
//! host-tested logic.
//!
//! A waiter that finds the lock held spins through [`SPIN_ATTEMPTS`] failed
//! acquisitions, then sleeps [`SLEEP_MS`] before each further attempt.
//! Under the kernel's strict-priority class (core/kernel/docs/scheduler.md
//! § Scheduling Classes), a CPU always runs its highest-level runnable
//! thread. A waiter that only spins never lets a lower-level holder queued
//! on its CPU run, so it would wait forever. The sleep blocks the waiter,
//! and the holder gets the CPU and releases the lock. The spins keep the
//! common case cheap, a holder that is running on another CPU and releases
//! within a short critical section. [`Backoff`] decides each step. The
//! acquisition and the sleep syscall stay with the caller. See
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(feature = "rustc-dep-of-std", feature(no_core))]
#![cfg_attr(feature = "rustc-dep-of-std", allow(internal_features))]
#![cfg_attr(not(feature = "rustc-dep-of-std"), no_std)]
#![cfg_attr(feature = "rustc-dep-of-std", no_core)]

#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_core as core;

#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

/// Failed acquisitions a waiter spins through before its first sleep.
///
/// A tuning threshold that bounds no capacity. It is a few tens of
/// microseconds of `pause` on current hardware: past the byte heap's
/// critical sections, short of a scheduler slice.
pub const SPIN_ATTEMPTS: u32 = 1024;

/// Milliseconds a waiter sleeps before each attempt past
/// [`SPIN_ATTEMPTS`]: the shortest `SYS_THREAD_SLEEP` that blocks. A
/// tuning value that bounds no capacity. Any blocking sleep lets a
/// lower-level holder on the waiter's CPU run, so a longer one only adds
/// latency.
pub const SLEEP_MS: u64 = 1;

/// What a waiter does after a failed acquisition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step
{
    /// Hint a spin-wait (`core::hint::spin_loop`) and try again.
    Spin,
    /// Sleep this many milliseconds, then try again.
    Sleep(u64),
}

/// The wait state of one acquisition: how many attempts have failed so far.
#[derive(Clone, Copy, Debug, Default)]
pub struct Backoff
{
    failed: u32,
}

impl Backoff
{
    /// A wait with no failed attempt yet.
    #[must_use]
    pub const fn new() -> Self
    {
        Self { failed: 0 }
    }

    /// Record a failed attempt and return what to do before the next one:
    /// [`Step::Spin`] for the first [`SPIN_ATTEMPTS`] failures, then
    /// [`Step::Sleep`] of [`SLEEP_MS`] for every later one, however many.
    pub fn next_step(&mut self) -> Step
    {
        if self.failed < SPIN_ATTEMPTS
        {
            self.failed += 1;
            Step::Spin
        }
        else
        {
            Step::Sleep(SLEEP_MS)
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn the_first_failures_spin()
    {
        let mut b = Backoff::new();
        for n in 0..SPIN_ATTEMPTS
        {
            assert_eq!(b.next_step(), Step::Spin, "failure {n} did not spin");
        }
    }

    #[test]
    fn the_failure_past_the_spin_bound_sleeps()
    {
        let mut b = Backoff::new();
        for _ in 0..SPIN_ATTEMPTS
        {
            b.next_step();
        }
        assert_eq!(b.next_step(), Step::Sleep(SLEEP_MS));
    }

    #[test]
    fn a_long_wait_keeps_sleeping_and_never_spins_again()
    {
        // A holder that never releases while the waiter only spins is the
        // livelock the sleep exists to break, so once the spins are spent no
        // later step may spin, however long the wait.
        let mut b = Backoff::new();
        for _ in 0..SPIN_ATTEMPTS
        {
            b.next_step();
        }
        for n in 0..(4 * SPIN_ATTEMPTS)
        {
            assert_eq!(
                b.next_step(),
                Step::Sleep(SLEEP_MS),
                "failure {n} past the bound did not sleep"
            );
        }
    }

    #[test]
    fn each_acquisition_starts_with_a_fresh_spin_budget()
    {
        let mut spent = Backoff::new();
        for _ in 0..=SPIN_ATTEMPTS
        {
            spent.next_step();
        }
        assert_eq!(spent.next_step(), Step::Sleep(SLEEP_MS));
        assert_eq!(Backoff::new().next_step(), Step::Spin);
        assert_eq!(Backoff::default().next_step(), Step::Spin);
    }

    #[test]
    fn the_sleep_blocks()
    {
        // SYS_THREAD_SLEEP with 0 ms does not block, and a sleep that does
        // not block leaves a lower-level holder on the waiter's CPU
        // starved.
        const { assert!(SLEEP_MS > 0) };
    }
}
