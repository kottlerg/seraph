// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/threads.rs

//! The threads a process registers with procmgr (`REGISTER_THREAD`), and the
//! crash badges that tell its threads' faults apart on the crash endpoint.
//!
//! Each thread the runtime spawns registers a Thread cap of its own; procmgr
//! keeps it in the process's [`ThreadRegistry`] until the thread exits, the
//! runtime revokes the cap when it reclaims the thread, or the process is torn
//! down. A thread whose exception class is bound under its sender's process
//! badge or under any crash badge (`ProcessEntry::is_crash_binding`), as one that
//! copied its spawner's bindings is, is rebound under a fresh crash badge
//! ([`CrashBadges`]), so the badge of a fault message names the faulting
//! thread. The registry holds slot indices
//! only; procmgr reads each slot's liveness and passes the answer in, so this
//! module is host-tested (`services/procmgr/docs/ipc-interface.md`
//! § `REGISTER_THREAD`).

extern crate alloc;

use alloc::vec::Vec;

use ipc::procmgr_labels::REGISTERED_THREADS_MAX;

/// The tag every thread crash badge carries: bit 63, a verb bit
/// (`ipc::VERB_BIT_MASK`) that no process badge carries
/// ([`crate::badge_is_acceptable`]), so a thread's crash badge never equals a
/// process badge and `ATTACH_PROCESS` tells the two kinds apart by it.
pub const CRASH_BADGE_TAG: u64 = 1 << 63;
const _: () = assert!(CRASH_BADGE_TAG & ipc::VERB_BIT_MASK != 0);

/// Registered threads below which a registration never sweeps: the first
/// sweep comes at this many, and later ones at twice what the last sweep
/// kept, or at the bound when that lies past it, each once half as many
/// requests as threads it reads came since the last
/// ([`ThreadRegistry::needs_sweep`]).
const FIRST_SWEEP_AT: usize = 64;

/// One registered thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisteredThread
{
    /// Slot in procmgr's `CSpace` of the thread's cap, with `OBSERVE`,
    /// `CONTROL`, and `UPCALL`.
    pub cap: u64,
    /// The badge procmgr bound the thread's exception class to the crash
    /// endpoint with; `0` when procmgr did not bind it (a debugger's binding,
    /// or no binding, was there).
    pub crash_badge: u64,
}

/// Why [`ThreadRegistry::reserve`] refused a registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterRefusal
{
    /// The process holds [`REGISTERED_THREADS_MAX`] threads (`THREAD_LIMIT`).
    Limit,
    /// The heap cannot grow the registry (`OUT_OF_MEMORY`).
    OutOfMemory,
}

/// The threads one process registered, in registration order: the order
/// `ATTACH_PROCESS` lists them in, after the main thread.
#[derive(Debug)]
pub struct ThreadRegistry
{
    threads: Vec<RegisteredThread>,
    /// The count at which the next registration sweeps out the threads that
    /// are gone.
    sweep_at: usize,
    /// Registrations, accepted or refused, since the last sweep: a sweep
    /// waits for at least half as many as the threads it reads.
    requests: usize,
}

impl Default for ThreadRegistry
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl ThreadRegistry
{
    /// An empty registry; it allocates nothing until the first registration.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            threads: Vec::new(),
            sweep_at: FIRST_SWEEP_AT,
            requests: 0,
        }
    }

    /// Number of registered threads, gone ones not yet swept included.
    #[must_use]
    pub fn len(&self) -> usize
    {
        self.threads.len()
    }

    /// Whether no thread is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool
    {
        self.threads.is_empty()
    }

    /// The registered thread at `index`.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<RegisteredThread>
    {
        self.threads.get(index).copied()
    }

    /// Whether the next registration sweeps first: the registry reached the
    /// count its last sweep set, or the bound when that count lies past it,
    /// and at least half as many registrations as it holds came since the
    /// last sweep. Below the bound the second holds whenever the first does,
    /// since the registry doubled from what that sweep kept; at the bound it
    /// spaces the sweeps. The requests between two sweeps therefore number at
    /// least half the threads a sweep reads, so the sweeps cost at most two
    /// thread-state reads per request on average, and threads that are gone
    /// hold the bound for at most half a registry's worth of requests.
    #[must_use]
    pub fn needs_sweep(&self) -> bool
    {
        let len = self.threads.len();
        len >= self.sweep_at.min(REGISTERED_THREADS_MAX) && self.requests >= len / 2
    }

    /// Drop every thread `is_live` reports gone, handing each to `dropped`
    /// (whose cap procmgr then deletes), keep the order of the rest, and set
    /// the next sweep at twice what is kept, at least [`FIRST_SWEEP_AT`].
    pub fn sweep(
        &mut self,
        mut is_live: impl FnMut(&RegisteredThread) -> bool,
        mut dropped: impl FnMut(RegisteredThread),
    )
    {
        self.threads.retain(|t| {
            let live = is_live(t);
            if !live
            {
                dropped(*t);
            }
            live
        });
        self.sweep_at = self.threads.len().saturating_mul(2).max(FIRST_SWEEP_AT);
        self.requests = 0;
    }

    /// Make room for one more thread, counting the request toward the next
    /// sweep ([`Self::needs_sweep`]) whether or not it is refused.
    ///
    /// # Errors
    /// [`RegisterRefusal::Limit`] at [`REGISTERED_THREADS_MAX`];
    /// [`RegisterRefusal::OutOfMemory`] when the heap cannot grow the registry.
    pub fn reserve(&mut self) -> Result<(), RegisterRefusal>
    {
        self.requests = self.requests.saturating_add(1);
        if self.threads.len() >= REGISTERED_THREADS_MAX
        {
            return Err(RegisterRefusal::Limit);
        }
        self.threads
            .try_reserve(1)
            .map_err(|_| RegisterRefusal::OutOfMemory)
    }

    /// Append `thread`, after a successful [`Self::reserve`].
    pub fn push(&mut self, thread: RegisteredThread)
    {
        debug_assert!(self.threads.len() < REGISTERED_THREADS_MAX);
        self.threads.push(thread);
    }

    /// The index of the thread bound under `crash_badge`.
    #[must_use]
    pub fn position_of_crash_badge(&self, crash_badge: u64) -> Option<usize>
    {
        if crash_badge == 0
        {
            return None;
        }
        self.threads
            .iter()
            .position(|t| t.crash_badge == crash_badge)
    }

    /// Remove and return every registered thread, for the teardown or the
    /// `DECLARE_NO_DEBUG` that releases them.
    pub fn take_all(&mut self) -> Vec<RegisteredThread>
    {
        self.sweep_at = FIRST_SWEEP_AT;
        self.requests = 0;
        core::mem::take(&mut self.threads)
    }
}

/// Mints thread crash badges: [`CRASH_BADGE_TAG`] above a count that never
/// repeats within a boot (2^63 badges), so no two threads share one. The
/// badge reaches only the crash endpoint's receiver, through the fault
/// messages of the thread it is bound to, and grants nothing; a count is
/// enough, and procmgr draws no entropy for it.
#[derive(Debug, Default)]
pub struct CrashBadges
{
    next: u64,
}

impl CrashBadges
{
    /// A minter whose first badge is `CRASH_BADGE_TAG | 1`.
    #[must_use]
    pub const fn new() -> Self
    {
        Self { next: 0 }
    }

    /// The next crash badge.
    pub fn mint(&mut self) -> u64
    {
        self.next = self.next.wrapping_add(1) & !CRASH_BADGE_TAG;
        if self.next == 0
        {
            self.next = 1;
        }
        CRASH_BADGE_TAG | self.next
    }
}

/// Whether `badge` is a thread crash badge rather than a process badge.
#[must_use]
pub fn is_crash_badge(badge: u64) -> bool
{
    badge & CRASH_BADGE_TAG != 0
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn thread(cap: u64, crash_badge: u64) -> RegisteredThread
    {
        RegisteredThread { cap, crash_badge }
    }

    #[test]
    fn a_registration_at_the_bound_is_refused()
    {
        let mut reg = ThreadRegistry::new();
        for i in 0..REGISTERED_THREADS_MAX as u64
        {
            assert_eq!(reg.reserve(), Ok(()));
            reg.push(thread(i + 1, 0));
        }
        assert_eq!(reg.reserve(), Err(RegisterRefusal::Limit));
        assert_eq!(reg.len(), REGISTERED_THREADS_MAX);
        // A sweep that finds a thread gone makes room again.
        reg.sweep(|t| t.cap != 1, |_| {});
        assert_eq!(reg.reserve(), Ok(()));
    }

    #[test]
    fn at_the_bound_a_sweep_waits_for_half_a_registry_of_requests()
    {
        let mut reg = ThreadRegistry::new();
        for i in 0..REGISTERED_THREADS_MAX as u64
        {
            if reg.needs_sweep()
            {
                reg.sweep(|_| true, |_| {});
            }
            reg.reserve().unwrap();
            reg.push(thread(i + 1, 0));
        }
        // Every thread live: the sweep at the bound keeps them all, and the
        // next one waits for half a registry's worth of requests.
        assert!(reg.needs_sweep());
        reg.sweep(|_| true, |_| {});
        for _ in 0..REGISTERED_THREADS_MAX / 2
        {
            assert!(!reg.needs_sweep());
            assert_eq!(reg.reserve(), Err(RegisterRefusal::Limit));
        }
        assert!(reg.needs_sweep());
    }

    #[test]
    fn threads_gone_after_a_large_sweep_hold_the_bound_for_half_a_registry_at_most()
    {
        // A sweep that keeps more than half the bound sets its next count
        // past the bound; the bound itself then becomes the sweep point.
        const NEW: u64 = 1 << 32;
        let kept = REGISTERED_THREADS_MAX / 2 + 100;
        let mut reg = ThreadRegistry::new();
        for i in 0..kept as u64
        {
            reg.push(thread(i + 1, 0));
        }
        reg.sweep(|_| true, |_| {});
        // Every one of those threads exits, and new ones keep registering.
        let mut refusals = 0;
        let mut swept_dead = false;
        for i in 0..2 * REGISTERED_THREADS_MAX as u64
        {
            if reg.needs_sweep()
            {
                reg.sweep(|t| t.cap >= NEW, |_| swept_dead = true);
            }
            match reg.reserve()
            {
                Ok(()) => reg.push(thread(NEW + i, 0)),
                Err(_) => refusals += 1,
            }
            if swept_dead
            {
                break;
            }
        }
        assert!(swept_dead, "the dead threads were never swept out");
        assert!(refusals <= REGISTERED_THREADS_MAX / 2);
        assert!(reg.len() < REGISTERED_THREADS_MAX);
        assert_eq!(reg.reserve(), Ok(()));
    }

    #[test]
    fn a_registration_sweeps_only_once_the_registry_doubles()
    {
        let mut reg = ThreadRegistry::new();
        for i in 0..FIRST_SWEEP_AT as u64
        {
            assert!(!reg.needs_sweep());
            reg.reserve().unwrap();
            reg.push(thread(i + 1, 0));
        }
        assert!(reg.needs_sweep());
        // Ten of the 64 stay live: the next sweep waits for the floor again.
        reg.sweep(|t| t.cap <= 10, |_| {});
        assert_eq!(reg.len(), 10);
        assert!(!reg.needs_sweep());
        // All 64 stay live: the next sweep waits for twice as many.
        let mut reg = ThreadRegistry::new();
        for i in 0..FIRST_SWEEP_AT as u64
        {
            reg.reserve().unwrap();
            reg.push(thread(i + 1, 0));
        }
        reg.sweep(|_| true, |_| {});
        for i in 0..FIRST_SWEEP_AT as u64
        {
            assert!(!reg.needs_sweep());
            reg.reserve().unwrap();
            reg.push(thread(100 + i, 0));
        }
        assert!(reg.needs_sweep());
    }

    #[test]
    fn a_sweep_hands_over_the_gone_threads_and_keeps_the_order_of_the_rest()
    {
        let mut reg = ThreadRegistry::new();
        for cap in [5, 6, 7, 8]
        {
            reg.reserve().unwrap();
            reg.push(thread(cap, 0));
        }
        let mut gone = Vec::new();
        reg.sweep(|t| t.cap % 2 == 0, |t| gone.push(t.cap));
        assert_eq!(gone, [5, 7]);
        assert_eq!(reg.get(0).map(|t| t.cap), Some(6));
        assert_eq!(reg.get(1).map(|t| t.cap), Some(8));
        assert_eq!(reg.get(2), None);
    }

    #[test]
    fn a_crash_badge_names_the_thread_bound_under_it_and_zero_names_none()
    {
        let mut reg = ThreadRegistry::new();
        for (cap, badge) in [(5, 0), (6, CRASH_BADGE_TAG | 9), (7, CRASH_BADGE_TAG | 4)]
        {
            reg.reserve().unwrap();
            reg.push(thread(cap, badge));
        }
        assert_eq!(reg.position_of_crash_badge(CRASH_BADGE_TAG | 4), Some(2));
        assert_eq!(reg.position_of_crash_badge(CRASH_BADGE_TAG | 9), Some(1));
        assert_eq!(reg.position_of_crash_badge(0), None);
        assert_eq!(reg.position_of_crash_badge(CRASH_BADGE_TAG | 5), None);
    }

    #[test]
    fn take_all_empties_the_registry_and_restarts_its_sweeps()
    {
        let mut reg = ThreadRegistry::new();
        for i in 0..FIRST_SWEEP_AT as u64
        {
            reg.reserve().unwrap();
            reg.push(thread(i + 1, 0));
        }
        assert_eq!(reg.take_all().len(), FIRST_SWEEP_AT);
        assert!(reg.is_empty());
        assert!(!reg.needs_sweep());
    }

    #[test]
    fn crash_badges_are_tagged_distinct_and_never_process_badges()
    {
        let mut badges = CrashBadges::new();
        let a = badges.mint();
        let b = badges.mint();
        assert_ne!(a, b);
        for badge in [a, b]
        {
            assert!(is_crash_badge(badge));
            assert!(!crate::badge_is_acceptable(
                badge,
                ipc::log_badges::LOG_BADGE_FIRST_CHILD,
                ipc::procmgr_labels::INIT_REAP_CORRELATOR,
                ipc::VERB_BIT_MASK
            ));
        }
        // The count past its top restarts at one, never at the bare tag.
        let mut wrapped = CrashBadges {
            next: !CRASH_BADGE_TAG,
        };
        assert_eq!(wrapped.mint(), CRASH_BADGE_TAG | 1);
    }
}
