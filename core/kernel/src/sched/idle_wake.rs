// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/sched/idle_wake.rs

//! A CPU's idle wake word: the flag its idle loop sets while it waits on the
//! word, and the word its wait watches for a store.
//!
//! On a CPU with a monitored wait (x86-64 `MONITOR`/`MWAIT`, riscv64 Zawrs
//! `WRS.NTO`), the idle loop sets [`POLLING`] before its last check of the run
//! queues and waits for a store to the word or an interrupt. A waker that links
//! a thread on that CPU clears the flag with one read-modify-write
//! ([`IdleWake::wake`]): when the flag was set, that clear is the store that
//! ends the wait and no wake IPI is sent. One atomic is both the flag and the
//! watched word, so every argument about a lost wake is about the modification
//! order of that one word
//! (core/kernel/docs/scheduling-internals.md § Wake Protocol Invariants).

use core::sync::atomic::{AtomicU32, Ordering};

/// The flag bit: set by the CPU's idle thread from just before its last run-queue
/// check until its wait ends, cleared by the first waker that sees it.
pub const POLLING: u32 = 1;

/// One CPU's idle wake word, alone in its 64-byte cache line so that a waker's
/// store to it shares the line with nothing else the CPU reads, and the
/// monitored range (one line on x86-64; the reservation set on riscv64) covers
/// no other field.
///
/// Written by the CPU's own idle thread ([`begin_poll`](Self::begin_poll),
/// [`end_poll`](Self::end_poll)) and by any CPU that wakes a thread onto this
/// one ([`wake`](Self::wake)); every write is a read-modify-write, so each
/// write reads the one before it in the word's modification order.
#[repr(align(64))]
pub struct IdleWake
{
    word: AtomicU32,
}

impl IdleWake
{
    /// A word with the flag clear.
    pub const fn new() -> Self
    {
        Self {
            word: AtomicU32::new(0),
        }
    }

    /// The word the idle wait watches.
    pub fn word(&self) -> &AtomicU32
    {
        &self.word
    }

    /// Set the flag. Called by the CPU's idle thread, with interrupts masked,
    /// before its last check of its run queues. Acquire: a waker whose
    /// [`wake`](Self::wake) precedes this swap in the word's order linked its
    /// thread before it, and the run-queue check after this swap sees the link.
    pub fn begin_poll(&self)
    {
        self.word.swap(POLLING, Ordering::AcqRel);
    }

    /// Clear the flag, before the idle thread runs anything but its idle loop.
    /// Returns whether a waker had cleared it first. Acquire for the reason
    /// [`begin_poll`](Self::begin_poll) is: a waker that skipped its IPI
    /// because it found the flag set made its clear before this one, so the
    /// dispatch that follows sees the thread it linked.
    pub fn end_poll(&self) -> bool
    {
        self.word.swap(0, Ordering::AcqRel) & POLLING == 0
    }

    /// Whether the flag is set, as of a Relaxed load.
    pub fn polling(&self) -> bool
    {
        self.word.load(Ordering::Relaxed) & POLLING != 0
    }

    /// Clear the flag for a waker that has linked a thread on this CPU's run
    /// queues. Returns `true` when this call cleared a set flag: its store ends
    /// the CPU's wait, or makes the CPU's re-check after it arms the wait skip
    /// the wait, and the waker sends no IPI. Returns `false` when the flag was
    /// clear, and the waker sends the IPI as on a CPU without the monitored
    /// wait. The first load only spares a busy CPU's line the write: a stale
    /// clear reading costs an IPI, never a lost wake. Release: the link this
    /// waker made precedes the clear the idle thread's next
    /// [`begin_poll`](Self::begin_poll) or [`end_poll`](Self::end_poll)
    /// reads.
    pub fn wake(&self) -> bool
    {
        if !self.polling()
        {
            return false;
        }
        self.word.fetch_and(!POLLING, Ordering::Release) & POLLING != 0
    }
}

#[cfg(test)]
mod tests
{
    //! Every interleaving of an idle CPU's loop with one waker, enumerated
    //! over the real [`IdleWake`] operations: the protocol loses no wake, and
    //! each known wrong order does.

    use super::*;

    /// How the two sides run. [`Protocol::CORRECT`] is the kernel's; every
    /// other value moves one step to a known wrong place.
    #[derive(Clone, Copy)]
    struct Protocol
    {
        /// The idle thread re-reads the flag after it arms the wait.
        recheck_after_arm: bool,
        /// The waker clears the flag with its read-modify-write; when false it
        /// skips the IPI on a plain read of the flag and stores nothing.
        waker_clears: bool,
        /// The idle thread clears the flag before it dispatches found work.
        clear_before_dispatch: bool,
    }

    impl Protocol
    {
        const CORRECT: Self = Self {
            recheck_after_arm: true,
            waker_clears: true,
            clear_before_dispatch: true,
        };
    }

    /// Where the idle thread is in its loop.
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    enum Idle
    {
        /// Interrupts masked, about to set the flag.
        Top,
        /// The flag is set and the run-queue check is next.
        Check,
        /// The check found nothing; arm the wait on the word.
        Arm,
        /// Waiting for a store after the arm, the IPI, or another interrupt.
        Wait,
        /// The wait ended or was skipped; clear the flag and loop.
        EndPoll,
        /// The check found work; clear the flag, then dispatch.
        FoundWork,
        /// Dispatch: the scheduler reads the run queues.
        Dispatch,
        /// Dispatched with the flag still set (the wrong order); clear it.
        LateClear,
        /// Running a thread.
        Running,
    }

    /// Where the waker is.
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    enum Waker
    {
        Link,
        Wake,
        Done,
    }

    /// One state of the two sides and the memory they share.
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    #[expect(
        clippy::struct_excessive_bools,
        reason = "each flag is one independent fact of the modelled machine"
    )]
    struct State
    {
        word: u32,
        idle: Idle,
        waker: Waker,
        /// The waker's thread is linked on the idle CPU's run queues.
        linked: bool,
        /// Another thread was queued from the start, so the first check finds
        /// work that is not the waker's.
        other_work: bool,
        /// The waker's IPI is pending at the idle CPU.
        ipi: bool,
        /// The waker's clear landed after the idle CPU armed its wait.
        store_after_arm: bool,
        /// Interrupts other than the IPI that may still end a wait.
        interrupts: u8,
        /// The dispatch saw the waker's thread.
        dispatched_it: bool,
    }

    /// Run one step of the idle thread, or `None` when it cannot move.
    fn idle_step(p: Protocol, mut s: State) -> Option<State>
    {
        let w = IdleWake::new();
        w.word.store(s.word, Ordering::Relaxed);
        s.idle = match s.idle
        {
            Idle::Top =>
            {
                w.begin_poll();
                Idle::Check
            }
            Idle::Check =>
            {
                if s.linked || s.other_work
                {
                    Idle::FoundWork
                }
                else
                {
                    Idle::Arm
                }
            }
            Idle::Arm =>
            {
                s.store_after_arm = false;
                if p.recheck_after_arm && !w.polling()
                {
                    Idle::EndPoll
                }
                else
                {
                    Idle::Wait
                }
            }
            Idle::Wait =>
            {
                if s.ipi
                {
                    s.ipi = false;
                }
                else if !s.store_after_arm
                {
                    if s.interrupts == 0
                    {
                        return None;
                    }
                    s.interrupts -= 1;
                }
                Idle::EndPoll
            }
            Idle::EndPoll =>
            {
                w.end_poll();
                Idle::Top
            }
            Idle::FoundWork if p.clear_before_dispatch =>
            {
                w.end_poll();
                Idle::Dispatch
            }
            Idle::FoundWork => Idle::Dispatch,
            Idle::Dispatch =>
            {
                s.dispatched_it = s.linked;
                s.other_work = false;
                if p.clear_before_dispatch
                {
                    Idle::Running
                }
                else
                {
                    Idle::LateClear
                }
            }
            Idle::LateClear =>
            {
                w.end_poll();
                Idle::Running
            }
            Idle::Running => return None,
        };
        s.word = w.word.load(Ordering::Relaxed);
        Some(s)
    }

    /// Run one step of the waker, or `None` when it is done.
    fn waker_step(p: Protocol, mut s: State) -> Option<State>
    {
        let w = IdleWake::new();
        w.word.store(s.word, Ordering::Relaxed);
        s.waker = match s.waker
        {
            Waker::Link =>
            {
                s.linked = true;
                Waker::Wake
            }
            Waker::Wake =>
            {
                let ended_poll = if p.waker_clears
                {
                    w.wake()
                }
                else
                {
                    w.polling()
                };
                if !ended_poll
                {
                    s.ipi = true;
                }
                else if p.waker_clears && matches!(s.idle, Idle::Wait)
                {
                    s.store_after_arm = true;
                }
                Waker::Done
            }
            Waker::Done => return None,
        };
        s.word = w.word.load(Ordering::Relaxed);
        Some(s)
    }

    /// Whether a final state lost the wake: the waker is done with its thread
    /// linked, the idle CPU can make no step, and neither the dispatch saw the
    /// thread nor is an IPI on its way to the thread the CPU runs.
    fn lost(s: State) -> bool
    {
        let stuck_waiting = s.idle == Idle::Wait;
        let ran_past_it = s.idle == Idle::Running && !s.dispatched_it && !s.ipi;
        s.waker == Waker::Done && (stuck_waiting || ran_past_it)
    }

    /// The first interleaving from `start` that loses the wake, as its trace
    /// of states, or `None` when none does.
    fn find_lost_wake(p: Protocol, start: State) -> Option<Vec<State>>
    {
        let mut seen = std::collections::HashSet::new();
        let mut stack = vec![vec![start]];
        while let Some(trace) = stack.pop()
        {
            let s = *trace.last().unwrap();
            if !seen.insert(s)
            {
                continue;
            }
            let next: Vec<State> = [idle_step(p, s), waker_step(p, s)]
                .into_iter()
                .flatten()
                .collect();
            if next.is_empty() && lost(s)
            {
                return Some(trace);
            }
            for n in next
            {
                let mut t = trace.clone();
                t.push(n);
                stack.push(t);
            }
        }
        None
    }

    /// What the idle CPU's run queues hold before the waker links its thread.
    #[derive(Clone, Copy)]
    enum Queued
    {
        Nothing,
        /// Another thread, so the first check finds work that is not the
        /// waker's.
        OtherThread,
    }

    fn start(queued: Queued, interrupts: u8) -> State
    {
        State {
            word: 0,
            idle: Idle::Top,
            waker: Waker::Link,
            linked: false,
            other_work: matches!(queued, Queued::OtherThread),
            ipi: false,
            store_after_arm: false,
            interrupts,
            dispatched_it: false,
        }
    }

    #[test]
    fn no_interleaving_of_the_idle_loop_and_a_waker_loses_the_wake()
    {
        assert_eq!(
            find_lost_wake(Protocol::CORRECT, start(Queued::Nothing, 0)),
            None
        );
    }

    #[test]
    fn an_interrupt_that_ends_the_wait_loses_no_wake()
    {
        assert_eq!(
            find_lost_wake(Protocol::CORRECT, start(Queued::Nothing, 2)),
            None
        );
    }

    #[test]
    fn a_waker_racing_the_clear_of_found_work_loses_no_wake()
    {
        assert_eq!(
            find_lost_wake(Protocol::CORRECT, start(Queued::OtherThread, 0)),
            None
        );
    }

    #[test]
    fn a_wait_armed_without_a_recheck_loses_a_wake()
    {
        let p = Protocol {
            recheck_after_arm: false,
            ..Protocol::CORRECT
        };
        assert!(find_lost_wake(p, start(Queued::Nothing, 0)).is_some());
    }

    #[test]
    fn a_waker_that_skips_the_ipi_on_a_plain_read_loses_a_wake()
    {
        let p = Protocol {
            waker_clears: false,
            ..Protocol::CORRECT
        };
        assert!(find_lost_wake(p, start(Queued::Nothing, 0)).is_some());
    }

    #[test]
    fn a_flag_cleared_after_the_dispatch_loses_a_wake()
    {
        let p = Protocol {
            clear_before_dispatch: false,
            ..Protocol::CORRECT
        };
        assert!(find_lost_wake(p, start(Queued::OtherThread, 0)).is_some());
    }
}
