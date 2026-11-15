// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/crashd/fault-bound/src/lib.rs

//! The state that bounds crashd's handling of one fault, shared by its
//! receiving thread and its watchdog thread.
//!
//! The receiver arms a generation for each bounded step of a fault's handling
//! ([`FaultBound::arm`]), with the step's own bound: the report's, then the
//! core dump's. The watchdog finds a generation past its deadline
//! ([`FaultBound::due`]) and commits to cancel it ([`FaultBound::commit`])
//! only while that generation is still armed, so a generation that ended
//! meanwhile is never cancelled, and then posts the receiver an upcall, which
//! cancels its blocking request, each tick while the generation stays
//! [`FaultBound::fired`]. The receiver checks [`FaultBound::fired`] before
//! each blocking request, so it starts none once the bound has passed, and
//! one a library call still sends is cancelled in its turn. A generation that
//! ends cancelled ([`FaultBound::end`]) is settled by the watchdog once its
//! last upcall is served or a post refused ([`FaultBound::settle`]), and the
//! receiver waits for that before it arms the next, so no upcall of one generation lands in the next one's handling
//! (`services/crashd/docs/operation.md` § Bounds). The state is atomics alone
//! and takes the time as an argument, so it is host-tested.

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
    /// When the armed generation's bound passes, in the caller's
    /// milliseconds.
    deadline_ms: AtomicU64,
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
            deadline_ms: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            settled: AtomicU64::new(0),
        }
    }

    /// Receiver: begin a bounded step at `now_ms`, due once `bound_ms` have
    /// passed, and return its generation. The previous generation has ended
    /// ([`Self::end`]), and been settled when it ended cancelled
    /// ([`Self::settled`]).
    pub fn arm(&self, now_ms: u64, bound_ms: u64) -> u64
    {
        let generation = self
            .generation
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.deadline_ms
            .store(now_ms.saturating_add(bound_ms), Ordering::Relaxed);
        // Release: a watchdog that reads this generation reads its deadline.
        self.armed.store(generation, Ordering::Release);
        generation
    }

    /// Whether the watchdog has committed to cancel `generation` and the
    /// receiver has not ended it. The receiver sends no request once it has;
    /// the watchdog cancels the receiver's requests until it no longer is.
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

    /// Watchdog: the armed generation whose deadline has passed at `now_ms`
    /// and that is not yet fired; `None` when there is none.
    #[must_use]
    pub fn due(&self, now_ms: u64) -> Option<u64>
    {
        let armed = self.armed.load(Ordering::Acquire);
        if armed == 0 || armed & FIRED != 0
        {
            return None;
        }
        let deadline = self.deadline_ms.load(Ordering::Relaxed);
        (now_ms >= deadline).then_some(armed)
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

    /// Watchdog: the cancellation of `generation` is finished: the
    /// receiver ended it and its last upcall was served, or a post was
    /// refused.
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
        assert_eq!(bound.due(5000), None);
        let g = bound.arm(1000, BOUND);
        assert_eq!(bound.due(1000 + BOUND - 1), None);
        assert!(!bound.fired(g));
        assert!(!bound.end(g));
        // An ended generation is never due.
        assert_eq!(bound.due(1000 + BOUND), None);
    }

    #[test]
    fn each_generation_is_due_at_its_own_bound()
    {
        // The report's step, then the dump's, with a longer bound.
        let bound = FaultBound::new();
        let report = bound.arm(0, BOUND);
        assert!(!bound.end(report));
        let dump = bound.arm(BOUND - 1, 10 * BOUND);
        assert_eq!(bound.due(2 * BOUND), None);
        assert_eq!(bound.due(11 * BOUND - 1), Some(dump));
        // A bound past the clock's end is never due.
        assert!(!bound.end(dump));
        let _ = bound.arm(1, u64::MAX);
        assert_eq!(bound.due(u64::MAX - 1), None);
    }

    #[test]
    fn a_committed_generation_is_fired_once_and_settled_by_the_watchdog()
    {
        let bound = FaultBound::new();
        let g = bound.arm(0, BOUND);
        assert_eq!(bound.due(BOUND), Some(g));
        assert!(bound.commit(g));
        assert!(bound.fired(g));
        // One cancellation per generation.
        assert_eq!(bound.due(2 * BOUND), None);
        assert!(!bound.commit(g));
        assert!(bound.end(g));
        assert!(!bound.settled(g));
        bound.settle(g);
        assert!(bound.settled(g));
    }

    #[test]
    fn a_fired_generation_stays_fired_until_the_receiver_ends_it()
    {
        // The watchdog cancels each request while the generation is fired,
        // and stops at its end, whatever the clock does meanwhile.
        let bound = FaultBound::new();
        let g = bound.arm(0, BOUND);
        assert!(bound.commit(g));
        for tick in 1..10
        {
            assert!(bound.fired(g));
            assert_eq!(bound.due(BOUND + tick * 100), None);
        }
        assert!(bound.end(g));
        assert!(!bound.fired(g));
        assert!(!bound.settled(g));
        bound.settle(g);
        assert!(bound.settled(g));
        let next = bound.arm(BOUND, BOUND);
        assert!(!bound.fired(next));
    }

    #[test]
    fn a_commit_that_loses_to_the_end_of_its_generation_cancels_nothing()
    {
        // The watchdog finds generation g past its bound, then the receiver
        // ends g and arms the next before the watchdog commits.
        let bound = FaultBound::new();
        let g = bound.arm(0, BOUND);
        assert_eq!(bound.due(BOUND), Some(g));
        assert!(!bound.end(g));
        let next = bound.arm(BOUND, BOUND);
        assert_ne!(next, g);
        assert!(!bound.commit(g));
        assert!(!bound.fired(next));
        assert!(!bound.end(next));
    }
}
