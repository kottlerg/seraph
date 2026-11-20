// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/sched/hold.rs

//! Address-space hold: the per-space hold state, the per-thread hold mark,
//! and the decisions the scheduler applies to them under its locks.
//!
//! `SYS_ASPACE_HOLD` stops every thread of an address space without
//! cancelling any park, and `SYS_ASPACE_RELEASE` starts again exactly the
//! threads the hold stopped. A `Ready` thread is stopped at once. A thread
//! that is `Running` or `Blocked` is marked [`HoldMark::Pending`] and keeps
//! running or stays parked; its next passage toward `Ready` (the wake that
//! ends its park, or the requeue of `schedule()` when it leaves its CPU)
//! commits `Stopped` instead, the wake's outcome already deposited in its
//! TCB. A start of a thread of the held space is deferred to the release.
//! The rules and their invariants are stated in
//! core/kernel/docs/thread-lifecycle-and-sleep.md § Address-Space Hold.
//!
//! This module holds only the decisions, as pure functions of the states, so
//! the host tests below can drive them through every reachable state of a
//! space; the code that applies them under `sched_lock` and the CPU locks
//! is in `sched/mod.rs`.

use super::thread::ThreadState;

/// The hold state of one address space (`AddressSpace::hold`).
///
/// A hold moves `Free` to `Holding` (refused in any other state), walks
/// the space's threads, waits until none is current on any CPU, and stores
/// `Held`. A release moves `Held` to `Releasing` (refused in any other
/// state), walks again, and stores `Free`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HoldState
{
    /// No hold: threads start and run as usual.
    Free = 0,
    /// A hold's walk or wait is in progress.
    Holding = 1,
    /// Every thread of the space is stopped or parked.
    Held = 2,
    /// A release's walk is in progress.
    Releasing = 3,
}

impl HoldState
{
    /// Decode the byte `AddressSpace::hold` stores; an unknown value, which
    /// no store writes, reads as `Free`.
    #[must_use]
    pub const fn from_u8(raw: u8) -> Self
    {
        match raw
        {
            1 => Self::Holding,
            2 => Self::Held,
            3 => Self::Releasing,
            _ => Self::Free,
        }
    }

    /// Whether a start of a thread of the space is deferred to the release.
    /// A start made while a release walks is not: the walk may already have
    /// passed the thread, and the release starts nothing it does not mark.
    #[must_use]
    pub const fn defers_start(self) -> bool
    {
        matches!(self, Self::Holding | Self::Held)
    }
}

/// What a hold or release has done to one thread (`ThreadControlBlock::hold`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldMark
{
    /// No hold applies to the thread.
    None,
    /// The hold found the thread `Running` or `Blocked`: its next passage
    /// toward `Ready` commits `Stopped` and moves the mark to
    /// [`HoldMark::Stopped`].
    Pending,
    /// The hold stopped the thread, diverted its passage toward `Ready`, or
    /// deferred its start; the release starts it.
    Stopped,
}

/// What a hold's walk does to one thread of the space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldVisit
{
    /// `Ready`: commit `Stopped` under every CPU lock, draining its run-queue
    /// link, and mark it [`HoldMark::Stopped`].
    Stop,
    /// `Running`: mark it [`HoldMark::Pending`] and prod its CPU, which
    /// diverts it at its next `schedule()`.
    MarkRunning,
    /// `Blocked`: mark it [`HoldMark::Pending`]; the wake that ends its park
    /// diverts it.
    MarkBlocked,
    /// `Created`, `Stopped` or `Exited`: nothing. A `Created` thread's start
    /// is deferred, and a thread a debugger stopped stays stopped.
    Leave,
}

/// The hold walk's decision for a thread in `state`.
#[must_use]
pub const fn hold_visit(state: ThreadState) -> HoldVisit
{
    match state
    {
        ThreadState::Ready => HoldVisit::Stop,
        ThreadState::Running => HoldVisit::MarkRunning,
        ThreadState::Blocked => HoldVisit::MarkBlocked,
        ThreadState::Created | ThreadState::Stopped | ThreadState::Exited => HoldVisit::Leave,
    }
}

/// Whether a thread carrying `mark` commits `Stopped` at its passage toward
/// `Ready` instead: the wake of its park (`enqueue_and_wake`'s `Blocked`
/// arm) or the requeue of a runnable outgoing thread (`schedule()`).
#[must_use]
pub const fn diverts(mark: HoldMark) -> bool
{
    matches!(mark, HoldMark::Pending)
}

/// What a `SYS_THREAD_START` commit does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartDecision
{
    /// Commit `Ready`; the start links the thread.
    Commit,
    /// The space is held: commit `Stopped` (from `Created` as from
    /// `Stopped`) and mark it [`HoldMark::Stopped`], linking nothing; the
    /// release starts it.
    Defer,
    /// Refused: the thread is neither `Created` nor `Stopped`, or it is
    /// stopped only by the hold, so that to its starter it is running.
    Refuse,
}

/// The start commit's decision for a thread in `state` carrying `mark`, of
/// a space in hold state `space`.
#[must_use]
pub const fn start_decision(space: HoldState, state: ThreadState, mark: HoldMark) -> StartDecision
{
    if !matches!(state, ThreadState::Created | ThreadState::Stopped)
        || matches!(mark, HoldMark::Stopped)
    {
        StartDecision::Refuse
    }
    else if space.defers_start()
    {
        StartDecision::Defer
    }
    else
    {
        StartDecision::Commit
    }
}

/// What a release's walk does to one thread of the space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseVisit
{
    /// Marked [`HoldMark::Stopped`]: start it (commit `Ready` and link it),
    /// clearing the mark, once it is settled; an unsettled one waits for the
    /// walk's next pass.
    Start,
    /// Marked [`HoldMark::Pending`]: clear the mark, so the wake of its park
    /// links it as usual.
    Clear,
    /// Unmarked: nothing.
    Leave,
}

/// The release walk's decision for a thread carrying `mark`.
#[must_use]
pub const fn release_visit(mark: HoldMark) -> ReleaseVisit
{
    match mark
    {
        HoldMark::Stopped => ReleaseVisit::Start,
        HoldMark::Pending => ReleaseVisit::Clear,
        HoldMark::None => ReleaseVisit::Leave,
    }
}

/// Whether `SYS_THREAD_STOP` refuses a thread in `state` carrying `mark`
/// (`InvalidState`). A thread stopped only by a hold is running to its
/// stopper: the stop succeeds and clears the mark, so the release leaves it
/// stopped.
#[must_use]
pub const fn stop_refused(state: ThreadState, mark: HoldMark) -> bool
{
    match state
    {
        ThreadState::Created | ThreadState::Exited => true,
        ThreadState::Stopped => !matches!(mark, HoldMark::Stopped),
        ThreadState::Ready | ThreadState::Running | ThreadState::Blocked => false,
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use std::collections::{HashSet, VecDeque};

    /// Threads in the modelled space.
    const N: usize = 3;

    /// One modelled thread: the scheduler's state and hold mark, whether a
    /// debugger stop (not the hold) is what holds it `Stopped`, and whether
    /// the hold or release walk in progress has visited it.
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Thread
    {
        state: ThreadState,
        mark: HoldMark,
        debug_stopped: bool,
        visited: bool,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Space
    {
        hold: HoldState,
        threads: [Thread; N],
    }

    impl Space
    {
        fn key(&self) -> u64
        {
            let mut key = self.hold as u64;
            for t in &self.threads
            {
                key = key * 64
                    + (t.state as u64) * 8
                    + (t.mark as u64) * 2
                    + u64::from(t.debug_stopped);
                key = key * 2 + u64::from(t.visited);
            }
            key
        }
    }

    /// Every event the kernel can apply to the space or to thread `i`, as the
    /// scheduler applies the decisions of this module. `None` when the event
    /// does not apply in this state.
    fn step(s: &Space, event: usize) -> Option<Space>
    {
        let (kind, i) = (event / N, event % N);
        if kind < 6
        {
            space_step(s, kind, i)
        }
        else
        {
            let mut n = *s;
            n.threads[i] = thread_step(s.hold, n.threads[i], kind)?;
            Some(n)
        }
    }

    /// The hold's and the release's own steps: begin (a compare-exchange of
    /// the space's state), the walk's visit of thread `i`, and the return.
    fn space_step(s: &Space, kind: usize, i: usize) -> Option<Space>
    {
        let mut n = *s;
        let all_visited = s.threads.iter().all(|t| t.visited);
        match kind
        {
            // SYS_ASPACE_HOLD's compare-exchange from Free.
            0 if i == 0 && s.hold == HoldState::Free =>
            {
                n.hold = HoldState::Holding;
                n.threads.iter_mut().for_each(|t| t.visited = false);
            }
            // The hold walk visits thread i.
            1 if s.hold == HoldState::Holding && !s.threads[i].visited =>
            {
                let t = &mut n.threads[i];
                t.visited = true;
                match hold_visit(t.state)
                {
                    HoldVisit::Stop =>
                    {
                        (t.state, t.mark) = (ThreadState::Stopped, HoldMark::Stopped);
                    }
                    HoldVisit::MarkRunning | HoldVisit::MarkBlocked => t.mark = HoldMark::Pending,
                    HoldVisit::Leave =>
                    {}
                }
            }
            // The hold returns: walked, and no thread of the space current.
            2 if i == 0
                && s.hold == HoldState::Holding
                && all_visited
                && s.threads.iter().all(|t| t.state != ThreadState::Running) =>
            {
                n.hold = HoldState::Held;
            }
            // SYS_ASPACE_RELEASE's compare-exchange from Held.
            3 if i == 0 && s.hold == HoldState::Held =>
            {
                n.hold = HoldState::Releasing;
                n.threads.iter_mut().for_each(|t| t.visited = false);
            }
            // The release walk visits thread i.
            4 if s.hold == HoldState::Releasing && !s.threads[i].visited =>
            {
                let t = &mut n.threads[i];
                t.visited = true;
                match release_visit(t.mark)
                {
                    ReleaseVisit::Start =>
                    {
                        assert!(
                            !t.debug_stopped,
                            "the release started a debugger-stopped thread"
                        );
                        (t.state, t.mark) = (ThreadState::Ready, HoldMark::None);
                    }
                    ReleaseVisit::Clear => t.mark = HoldMark::None,
                    ReleaseVisit::Leave =>
                    {}
                }
            }
            // The release returns.
            5 if i == 0 && s.hold == HoldState::Releasing && all_visited =>
            {
                n.hold = HoldState::Free;
            }
            _ => return None,
        }
        Some(n)
    }

    /// The steps of one thread `t` of a space in hold state `hold`.
    fn thread_step(hold: HoldState, mut t: Thread, kind: usize) -> Option<Thread>
    {
        match kind
        {
            // The wake that ends a park (a reply, a send, a timer, a cancel),
            // or a running thread leaving its CPU runnable (preemption, a
            // yield, a refused park: schedule()'s requeue).
            6 | 7
                if (kind == 6 && t.state == ThreadState::Blocked)
                    || (kind == 7 && t.state == ThreadState::Running) =>
            {
                if diverts(t.mark)
                {
                    (t.state, t.mark) = (ThreadState::Stopped, HoldMark::Stopped);
                }
                else
                {
                    t.state = ThreadState::Ready;
                }
            }
            // A running thread commits a park.
            8 if t.state == ThreadState::Running => t.state = ThreadState::Blocked,
            // A CPU dispatches a ready thread.
            9 if t.state == ThreadState::Ready => t.state = ThreadState::Running,
            // SYS_THREAD_START.
            10 => match start_decision(hold, t.state, t.mark)
            {
                StartDecision::Commit => (t.state, t.debug_stopped) = (ThreadState::Ready, false),
                StartDecision::Defer =>
                {
                    (t.state, t.mark, t.debug_stopped) =
                        (ThreadState::Stopped, HoldMark::Stopped, false);
                }
                StartDecision::Refuse => return None,
            },
            // SYS_THREAD_STOP (a debugger), which cancels any park.
            11 if !stop_refused(t.state, t.mark) =>
            {
                (t.state, t.mark, t.debug_stopped) = (ThreadState::Stopped, HoldMark::None, true);
            }
            // An exit, or the teardown of the space: Exited clears the mark.
            12 if t.state != ThreadState::Exited =>
            {
                (t.state, t.mark, t.debug_stopped) = (ThreadState::Exited, HoldMark::None, false);
            }
            _ => return None,
        }
        Some(t)
    }

    /// The hold's invariants (core/kernel/docs/thread-lifecycle-and-sleep.md
    /// § Address-Space Hold), checked on one reachable state.
    fn check(s: &Space)
    {
        for t in &s.threads
        {
            match t.mark
            {
                HoldMark::Stopped =>
                {
                    assert_eq!(t.state, ThreadState::Stopped, "a hold-stopped thread runs");
                }
                HoldMark::Pending => assert!(
                    matches!(t.state, ThreadState::Running | ThreadState::Blocked),
                    "a pending mark outlived the thread's run or park"
                ),
                HoldMark::None =>
                {}
            }
            if t.debug_stopped
            {
                assert_eq!(t.state, ThreadState::Stopped, "a debugger stop was undone");
                assert_eq!(
                    t.mark,
                    HoldMark::None,
                    "the release would start a debugger-stopped thread"
                );
            }
            // Containment: a thread the hold has reached is never made runnable
            // while the space is held, and only one already running at the
            // hold may still run until it leaves its CPU.
            let reached = match s.hold
            {
                HoldState::Holding => t.visited,
                HoldState::Held => true,
                HoldState::Free | HoldState::Releasing => false,
            };
            if reached
            {
                assert_ne!(
                    t.state,
                    ThreadState::Ready,
                    "a held thread was made runnable"
                );
                if t.state == ThreadState::Running
                {
                    assert_eq!(t.mark, HoldMark::Pending, "a held thread runs unmarked");
                }
            }
        }
        if s.hold == HoldState::Free
        {
            assert!(
                s.threads.iter().all(|t| t.mark == HoldMark::None),
                "a mark survived the release"
            );
        }
    }

    #[test]
    fn every_reachable_state_of_a_held_and_released_space_keeps_the_hold_invariants()
    {
        let starts = [
            (ThreadState::Created, false),
            (ThreadState::Ready, false),
            (ThreadState::Running, false),
            (ThreadState::Blocked, false),
            (ThreadState::Stopped, true),
            (ThreadState::Exited, false),
        ];
        let mut seen = HashSet::new();
        let mut queue = VecDeque::new();
        for a in starts
        {
            for b in starts
            {
                for c in starts
                {
                    let thread = |(state, debug_stopped): (ThreadState, bool)| Thread {
                        state,
                        mark: HoldMark::None,
                        debug_stopped,
                        visited: false,
                    };
                    let s = Space {
                        hold: HoldState::Free,
                        threads: [thread(a), thread(b), thread(c)],
                    };
                    if seen.insert(s.key())
                    {
                        queue.push_back(s);
                    }
                }
            }
        }
        let mut released = 0usize;
        while let Some(s) = queue.pop_front()
        {
            check(&s);
            for event in 0..13 * N
            {
                if let Some(next) = step(&s, event)
                {
                    if s.hold == HoldState::Releasing && next.hold == HoldState::Free
                    {
                        released += 1;
                    }
                    if seen.insert(next.key())
                    {
                        queue.push_back(next);
                    }
                }
            }
        }
        // The exploration reached complete holds and releases, not only the
        // initial states.
        assert!(released > 0);
        assert!(seen.iter().any(|&k| k >> (7 * N) == HoldState::Held as u64));
    }

    #[test]
    fn a_wake_during_the_hold_stops_its_thread_and_the_release_starts_it()
    {
        let blocked = Thread {
            state: ThreadState::Blocked,
            mark: HoldMark::None,
            debug_stopped: false,
            visited: false,
        };
        let mut s = Space {
            hold: HoldState::Free,
            threads: [blocked; N],
        };
        // Hold, walk, return.
        s = step(&s, 0).unwrap();
        for i in 0..N
        {
            s = step(&s, N + i).unwrap();
        }
        s = step(&s, 2 * N).unwrap();
        assert_eq!(s.hold, HoldState::Held);
        // The park of thread 0 ends during the hold: its outcome is deposited
        // but it is stopped, not made runnable.
        s = step(&s, 6 * N).unwrap();
        assert_eq!(s.threads[0].state, ThreadState::Stopped);
        // Release: thread 0 runs again; threads 1 and 2 stay parked, unmarked.
        s = step(&s, 3 * N).unwrap();
        for i in 0..N
        {
            s = step(&s, 4 * N + i).unwrap();
        }
        s = step(&s, 5 * N).unwrap();
        assert_eq!(s.threads[0].state, ThreadState::Ready);
        assert_eq!(s.threads[1].state, ThreadState::Blocked);
        assert_eq!(s.threads[1].mark, HoldMark::None);
    }
}
