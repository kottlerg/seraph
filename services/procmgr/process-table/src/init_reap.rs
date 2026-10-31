// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/init_reap.rs

//! State machine of procmgr's init-reap handoff (`REGISTER_INIT_TEARDOWN`,
//! `INIT_TEARDOWN_DONE`, and the two init-thread deaths).
//!
//! procmgr's `init_reap` module drives it and does the syscalls and IPC; this
//! machine decides which sender and which request is accepted and when the
//! reap runs, so the gate, the one-shot handoff, and the death countdown are
//! host-tested. The protocol is in `services/procmgr/docs/ipc-interface.md`
//! § `REGISTER_INIT_TEARDOWN` and § `INIT_TEARDOWN_DONE`.
//!
//! ```text
//! Empty ──first round (badge 0, 4 caps)──▶ Collecting{pending_deaths: 2}
//! Collecting ──donation round (badge 0)──▶ Collecting
//! Collecting ──INIT_TEARDOWN_DONE (badge 0, once)──▶ Collecting{armed}
//! Collecting ──death──▶ Collecting{pending_deaths - 1}
//! Collecting ──last death──▶ Reaped   (the caller runs the teardown)
//! ```
//!
//! `Reaped` is terminal: the handoff happens once per boot.

/// Init threads whose deaths the reap waits for: main and init-logd.
pub const INIT_THREADS: u8 = 2;

/// Kernel-object caps the first round carries: `AddressSpace`, `CSpace`,
/// main `Thread`, init-logd `Thread`.
pub const FIRST_ROUND_CAPS: usize = 4;

/// Why a handoff request is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal
{
    /// The sender's badge is not 0, so it is not init. Its caps are not
    /// init's, and procmgr deletes them; reply `UNAUTHORIZED`.
    Unauthorized,
    /// An un-badged request that does not fit the handoff's state or shape.
    /// Reply `INVALID_ARGUMENT`.
    Invalid(CapDisposition),
}

/// What procmgr does with the caps a refused un-badged request moved into
/// its `CSpace`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapDisposition
{
    /// Leave them. While the handoff is open, init still runs on the
    /// `AddressSpace` a first round carries and still maps the Memory caps a
    /// donation round carries, so deleting them could tear down a live
    /// address space or free mapped pages.
    Keep,
    /// Delete them. After the reap, init is gone and no live mapping of its
    /// depends on them.
    Release,
}

/// What a death event does to the handoff.
#[derive(Debug, PartialEq, Eq)]
pub enum DeathOutcome<T>
{
    /// No handoff is open; the event is stale.
    Ignored,
    /// The death is counted; this many init threads still run.
    Pending(u8),
    /// The last init thread exited: the caller tears init down with the
    /// collected state.
    Reap(T),
}

/// The handoff state, holding the caller's collected caps `T`.
pub enum InitReap<T>
{
    /// No first round accepted yet.
    Empty,
    /// The first round was accepted; donation rounds append to `held`.
    Collecting
    {
        /// The caller's collected caps: the first round's kernel-object
        /// caps and every donation round's Memory caps.
        held: T,
        /// `INIT_TEARDOWN_DONE` was received.
        armed: bool,
        /// Init threads that have not exited yet.
        pending_deaths: u8,
    },
    /// The reap ran. Every further request is refused.
    Reaped,
}

impl<T> InitReap<T>
{
    /// An empty handoff: no first round accepted yet.
    #[must_use]
    pub const fn new() -> Self
    {
        Self::Empty
    }

    /// Whether a first round from `badge` carrying `cap_count` caps may open
    /// the handoff. On `Ok` the caller binds its death observers on both init
    /// threads and then calls [`Self::open`].
    ///
    /// # Errors
    /// [`Refusal::Unauthorized`] for a badged sender; [`Refusal::Invalid`]
    /// when a handoff is already open (keep the caps), after the reap
    /// (release them), or when the round does not carry
    /// [`FIRST_ROUND_CAPS`] caps (keep them).
    pub fn check_first_round(&self, badge: u64, cap_count: usize) -> Result<(), Refusal>
    {
        if badge != 0
        {
            return Err(Refusal::Unauthorized);
        }
        match self
        {
            Self::Collecting { .. } => Err(Refusal::Invalid(CapDisposition::Keep)),
            Self::Reaped => Err(Refusal::Invalid(CapDisposition::Release)),
            Self::Empty if cap_count != FIRST_ROUND_CAPS =>
            {
                Err(Refusal::Invalid(CapDisposition::Keep))
            }
            Self::Empty => Ok(()),
        }
    }

    /// Open the handoff with the first round's caps, expecting
    /// [`INIT_THREADS`] deaths. Call only after [`Self::check_first_round`]
    /// accepted the round and both death observers are bound.
    pub fn open(&mut self, held: T)
    {
        *self = Self::Collecting {
            held,
            armed: false,
            pending_deaths: INIT_THREADS,
        };
    }

    /// Accept a donation round from `badge`, returning the collected state
    /// to append its caps to.
    ///
    /// # Errors
    /// [`Refusal::Unauthorized`] for a badged sender; [`Refusal::Invalid`]
    /// before the first round (keep the caps) or after the reap (release
    /// them).
    pub fn donation(&mut self, badge: u64) -> Result<&mut T, Refusal>
    {
        if badge != 0
        {
            return Err(Refusal::Unauthorized);
        }
        match self
        {
            Self::Collecting { held, .. } => Ok(held),
            Self::Empty => Err(Refusal::Invalid(CapDisposition::Keep)),
            Self::Reaped => Err(Refusal::Invalid(CapDisposition::Release)),
        }
    }

    /// Accept `INIT_TEARDOWN_DONE` from `badge`.
    ///
    /// # Errors
    /// [`Refusal::Unauthorized`] for a badged sender; [`Refusal::Invalid`]
    /// with no open handoff, after the reap, or when already armed. The
    /// message carries no caps the protocol names, so any it moved are
    /// released.
    pub fn done(&mut self, badge: u64) -> Result<(), Refusal>
    {
        if badge != 0
        {
            return Err(Refusal::Unauthorized);
        }
        match self
        {
            Self::Collecting { armed, .. } if !*armed =>
            {
                *armed = true;
                Ok(())
            }
            _ => Err(Refusal::Invalid(CapDisposition::Release)),
        }
    }

    /// Count one init-thread death. The last one moves the handoff to
    /// [`InitReap::Reaped`] and hands the collected state back for the
    /// teardown, armed or not: a threadless init can send no further round,
    /// so waiting for `INIT_TEARDOWN_DONE` would strand the reap.
    pub fn death(&mut self) -> DeathOutcome<T>
    {
        let Self::Collecting { pending_deaths, .. } = self
        else
        {
            return DeathOutcome::Ignored;
        };
        *pending_deaths = pending_deaths.saturating_sub(1);
        if *pending_deaths > 0
        {
            return DeathOutcome::Pending(*pending_deaths);
        }
        match core::mem::replace(self, Self::Reaped)
        {
            Self::Collecting { held, .. } => DeathOutcome::Reap(held),
            // Matched as `Collecting` above; the other arms cannot occur.
            Self::Empty | Self::Reaped => DeathOutcome::Ignored,
        }
    }
}

impl<T> Default for InitReap<T>
{
    fn default() -> Self
    {
        Self::new()
    }
}

/// Retry `attempt` until it succeeds or `budget_ns` of `now_ns` time has
/// passed since the first try, calling `pause` between tries. Returns whether
/// an attempt succeeded.
///
/// The bound is wall-clock time, not a count of tries, so a loaded system
/// that stretches each pause does not exhaust it early; the first try always
/// runs, whatever the budget. procmgr's init reap waits out the release of
/// init's `CSpace` with it.
pub fn poll_within(
    budget_ns: u64,
    mut now_ns: impl FnMut() -> u64,
    mut attempt: impl FnMut() -> bool,
    mut pause: impl FnMut(),
) -> bool
{
    let start = now_ns();
    loop
    {
        if attempt()
        {
            return true;
        }
        if now_ns().saturating_sub(start) >= budget_ns
        {
            return false;
        }
        pause();
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn opened() -> InitReap<u32>
    {
        let mut m = InitReap::new();
        assert_eq!(m.check_first_round(0, FIRST_ROUND_CAPS), Ok(()));
        m.open(7);
        m
    }

    #[test]
    fn badged_sender_is_refused_on_every_handoff_label()
    {
        let mut m = opened();
        assert_eq!(
            InitReap::<u32>::new().check_first_round(16, FIRST_ROUND_CAPS),
            Err(Refusal::Unauthorized)
        );
        assert_eq!(m.donation(16).err(), Some(Refusal::Unauthorized));
        assert_eq!(m.done(16), Err(Refusal::Unauthorized));
        // A refused DONE does not arm the handoff: init's own DONE still
        // succeeds.
        assert_eq!(m.done(0), Ok(()));
    }

    #[test]
    fn first_round_is_refused_with_the_wrong_cap_count_or_while_open()
    {
        let empty = InitReap::<u32>::new();
        assert_eq!(
            empty.check_first_round(0, 3),
            Err(Refusal::Invalid(CapDisposition::Keep))
        );
        assert_eq!(
            opened().check_first_round(0, FIRST_ROUND_CAPS),
            Err(Refusal::Invalid(CapDisposition::Keep))
        );
    }

    #[test]
    fn donation_before_the_first_round_is_refused()
    {
        let mut empty = InitReap::<u32>::new();
        assert_eq!(
            empty.donation(0).err(),
            Some(Refusal::Invalid(CapDisposition::Keep))
        );
    }

    #[test]
    fn donation_into_an_open_handoff_reaches_the_reap()
    {
        let mut m = opened();
        *m.donation(0).expect("open handoff accepts donations") += 1;
        assert_eq!(m.death(), DeathOutcome::Pending(1));
        assert_eq!(m.death(), DeathOutcome::Reap(8));
    }

    #[test]
    fn done_twice_is_refused()
    {
        let mut m = opened();
        assert_eq!(m.done(0), Ok(()));
        assert_eq!(m.done(0), Err(Refusal::Invalid(CapDisposition::Release)));
    }

    #[test]
    fn reap_runs_on_the_second_death_when_armed()
    {
        let mut m = opened();
        assert_eq!(m.death(), DeathOutcome::Pending(1));
        assert_eq!(m.done(0), Ok(()));
        assert_eq!(m.death(), DeathOutcome::Reap(7));
    }

    #[test]
    fn double_death_before_arming_still_reaps()
    {
        let mut m = opened();
        assert_eq!(m.death(), DeathOutcome::Pending(1));
        assert_eq!(m.death(), DeathOutcome::Reap(7));
    }

    #[test]
    fn handoff_is_one_shot_after_the_reap()
    {
        let mut m = opened();
        let _ = m.death();
        let _ = m.death();
        assert_eq!(m.death(), DeathOutcome::Ignored);
        assert_eq!(
            m.check_first_round(0, FIRST_ROUND_CAPS),
            Err(Refusal::Invalid(CapDisposition::Release))
        );
        assert_eq!(
            m.donation(0).err(),
            Some(Refusal::Invalid(CapDisposition::Release))
        );
        assert_eq!(m.done(0), Err(Refusal::Invalid(CapDisposition::Release)));
    }

    #[test]
    fn death_with_no_open_handoff_is_ignored()
    {
        assert_eq!(InitReap::<u32>::new().death(), DeathOutcome::Ignored);
    }

    #[test]
    fn poll_within_outlasts_any_try_count_until_the_budget_is_spent()
    {
        // The clock advances one unit per pause: 10_000 tries fit a budget of
        // 10_000 units, far past the former 64-try bound.
        let clock = core::cell::Cell::new(0u64);
        let mut tries = 0u32;
        let ok = poll_within(
            10_000,
            || clock.get(),
            || {
                tries += 1;
                tries == 10_000
            },
            || clock.set(clock.get() + 1),
        );
        assert!(ok);
        assert_eq!(tries, 10_000);
    }

    #[test]
    fn poll_within_gives_up_once_the_budget_has_passed()
    {
        let clock = core::cell::Cell::new(0u64);
        let mut tries = 0u32;
        let ok = poll_within(
            5,
            || clock.get(),
            || {
                tries += 1;
                false
            },
            || clock.set(clock.get() + 2),
        );
        assert!(!ok);
        // Tries at t = 0, 2, 4, 6; the check after the fourth sees 6 >= 5.
        assert_eq!(tries, 4);
    }

    #[test]
    fn poll_within_tries_once_on_a_zero_budget()
    {
        let mut tries = 0u32;
        assert!(!poll_within(
            0,
            || 7,
            || {
                tries += 1;
                false
            },
            || {}
        ));
        assert_eq!(tries, 1);
        assert!(poll_within(
            0,
            || 7,
            || true,
            || panic!("no pause after success")
        ));
    }
}
