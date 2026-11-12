// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/crashd/fault-bound/src/lib.rs

//! The state that bounds crashd's handling of one fault, shared by its
//! receiving thread and its watchdog thread.
//!
//! The receiver arms a generation for each fault ([`FaultBound::arm`]). The
//! watchdog finds a generation past its bound ([`FaultBound::due`]) and
//! commits to cancel it ([`FaultBound::commit`]) only while that generation
//! is still armed, so a generation that ended meanwhile is never cancelled,
//! and then posts the receiver the upcall that cancels its blocking request.
//! The receiver checks [`FaultBound::fired`] before each blocking request, so
//! none is sent once the bound has passed. A generation that ends cancelled
//! ([`FaultBound::end`]) is settled by the watchdog once its upcall is served
//! or its post refused ([`FaultBound::settle`]), and the receiver waits for
//! that before it arms the next, so no upcall of one generation lands in the
//! next one's handling (`services/crashd/docs/operation.md` § Bounds). The
//! state is atomics alone and takes the time as an argument, so it is
//! host-tested.

// Staged roll-out of these two lints: docs/coding-standards.md § Clippy.
#![warn(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
#![cfg_attr(not(test), no_std)]

use core::sync::atomic::{AtomicU64, Ordering};

/// Set in the armed word once the watchdog has committed to cancel the
/// generation it holds. Generations count from 1 and never reach this bit
/// within a boot (2^63 faults).
const FIRED: u64 = 1 << 63;

/// The bound of one fault's handling at a time.
#[derive(Debug, Default)]
pub struct FaultBound
{
    /// The generation being handled, `0` while none is, with [`FIRED`] set
    /// once the watchdog committed to cancel it.
    armed: AtomicU64,
    /// When the armed generation began, in the caller's milliseconds.
    armed_at_ms: AtomicU64,
    /// The last generation armed; the receiver alone writes it.
    generation: AtomicU64,
    /// The last generation whose cancellation the watchdog has finished.
    settled: AtomicU64,
}

impl FaultBound
{
    /// No generation armed, none fired.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            armed: AtomicU64::new(0),
            armed_at_ms: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            settled: AtomicU64::new(0),
        }
    }

    /// Receiver: begin a fault's handling at `now_ms` and return its
    /// generation. The previous generation has ended ([`Self::end`]), and
    /// been settled when it ended cancelled ([`Self::settled`]).
    pub fn arm(&self, now_ms: u64) -> u64
    {
        let generation = self
            .generation
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.armed_at_ms.store(now_ms, Ordering::Relaxed);
        // Release: a watchdog that reads this generation reads its start.
        self.armed.store(generation, Ordering::Release);
        generation
    }

    /// Receiver: whether the watchdog has committed to cancel `generation`,
    /// the armed one. A request is not sent once it has.
    #[must_use]
    pub fn fired(&self, generation: u64) -> bool
    {
        self.armed.load(Ordering::Acquire) == generation | FIRED
    }

    /// Receiver: end `generation`'s handling. Returns whether the watchdog
    /// committed to cancel it: its upcall is then posted or about to be, and
    /// the receiver waits for [`Self::settled`] before it blocks for the next
    /// fault's handling.
    pub fn end(&self, generation: u64) -> bool
    {
        self.armed.swap(0, Ordering::AcqRel) == generation | FIRED
    }

    /// Receiver: whether the watchdog has finished the cancellation of
    /// `generation`.
    #[must_use]
    pub fn settled(&self, generation: u64) -> bool
    {
        self.settled.load(Ordering::Acquire) >= generation
    }

    /// Watchdog: the generation armed at `now_ms` for `bound_ms` or more and
    /// not yet fired; `None` when there is none.
    #[must_use]
    pub fn due(&self, now_ms: u64, bound_ms: u64) -> Option<u64>
    {
        let armed = self.armed.load(Ordering::Acquire);
        if armed == 0 || armed & FIRED != 0
        {
            return None;
        }
        let at = self.armed_at_ms.load(Ordering::Relaxed);
        (now_ms.saturating_sub(at) >= bound_ms).then_some(armed)
    }

    /// Watchdog: commit to cancel `generation`, which [`Self::due`] returned.
    /// Returns `false`, committing nothing, when that generation has ended
    /// since; the watchdog then posts nothing, and a later generation's
    /// handling is not cut short.
    pub fn commit(&self, generation: u64) -> bool
    {
        self.armed
            .compare_exchange(
                generation,
                generation | FIRED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Watchdog: the cancellation of `generation` is finished: its upcall
    /// was served, or its post refused.
    pub fn settle(&self, generation: u64)
    {
        self.settled.fetch_max(generation, Ordering::Release);
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const BOUND: u64 = 2000;

    #[test]
    fn a_generation_is_not_due_before_its_bound_passes()
    {
        let bound = FaultBound::new();
        assert_eq!(bound.due(5000, BOUND), None);
        let g = bound.arm(1000);
        assert_eq!(bound.due(1000 + BOUND - 1, BOUND), None);
        assert!(!bound.fired(g));
        assert!(!bound.end(g));
        // An ended generation is never due.
        assert_eq!(bound.due(1000 + BOUND, BOUND), None);
    }

    #[test]
    fn a_committed_generation_is_fired_once_and_settled_by_the_watchdog()
    {
        let bound = FaultBound::new();
        let g = bound.arm(0);
        assert_eq!(bound.due(BOUND, BOUND), Some(g));
        assert!(bound.commit(g));
        assert!(bound.fired(g));
        // One cancellation per generation.
        assert_eq!(bound.due(2 * BOUND, BOUND), None);
        assert!(!bound.commit(g));
        assert!(bound.end(g));
        assert!(!bound.settled(g));
        bound.settle(g);
        assert!(bound.settled(g));
    }

    #[test]
    fn a_commit_that_loses_to_the_end_of_its_generation_cancels_nothing()
    {
        // The watchdog finds generation g past its bound, then the receiver
        // ends g and arms the next before the watchdog commits.
        let bound = FaultBound::new();
        let g = bound.arm(0);
        assert_eq!(bound.due(BOUND, BOUND), Some(g));
        assert!(!bound.end(g));
        let next = bound.arm(BOUND);
        assert_ne!(next, g);
        assert!(!bound.commit(g));
        assert!(!bound.fired(next));
        assert!(!bound.end(next));
    }
}
