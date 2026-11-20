// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/svc-defs/src/memory_wait.rs

//! The memory wait: the state machine of a restart whose `CREATE_FROM_FILE`
//! procmgr refused for want of memory, which svcmgr's restart path
//! (`restart.rs`) and main loop drive
//! (`services/svcmgr/docs/restart-protocol.md` § Decision tree, the memory
//! wait).
//!
//! memmgr refuses a request from a budget node outside the system reserve
//! that would leave fewer free pages outside `promised` than the growth floor
//! (`services/memmgr/docs/memory-pool.md` § Allocation), and procmgr's create
//! of such a service then replies `OUT_OF_MEMORY`. Its pressure level reads
//! `CRITICAL` at or below that floor, and leaves it only once the free pool
//! clears the floor by a hysteresis band (§ Memory pressure), so a create
//! needing more than the margin above the floor is refused below `CRITICAL`
//! too, as is one needing a contiguous run memmgr cannot find. Only memory
//! coming free ends such a refusal. memmgr signals a change of level on the
//! Notification the std runtime registers for every process, but memory can
//! come free below `CRITICAL` with no change of level, so svcmgr also retries
//! on a timer while the level reads below.
//!
//! The states of one service's restart, and the events that move it:
//!
//! - **Decided**: its death's restart was charged to the budget once
//!   (`should_restart`) and its create made. A refusal
//!   ([`MemoryWaits::on_refusal`] with [`Refused::Decided`]) moves it to
//!   *waiting* when the failure is `OUT_OF_MEMORY` and the service may wait,
//!   and *down* otherwise.
//! - **Waiting** ([`MemoryWait`]; the entry is inactive and holds no instance,
//!   so no death post routes to it and no reader reports it running). svcmgr's
//!   level ([`MemoryWaits::record_level`]) decides the wake: at `CRITICAL`, or
//!   unread, nothing retries it and the main loop waits with no timeout; below
//!   `CRITICAL` a signal of a change of level retries it at once, and the main
//!   loop waits at most [`MEMORY_RETRY_MS`], whose expiry retries it
//!   ([`MemoryWaits::wake`], [`MemoryWaits::wait_timeout_ms`]).
//! - **Retry**: the create is made again, charging the budget nothing: the
//!   death it restarts was charged. Success leaves the wait: the service runs.
//!   A new instance that dies during its bootstrap is a new death, decided
//!   from the start and charged. A refusal ([`Refused::Retried`]) for want of
//!   memory moves it back to *waiting*, counting a timed retry, and to *down*
//!   once the timed retries reach [`MEMORY_RETRY_LIMIT`]; any other failure
//!   moves it to *down*.
//! - **Down**: permanently down, as for any failure; its `critical` key
//!   decides the rest.

use ipc::memmgr_labels::PRESSURE_CRITICAL;

/// The interval, in milliseconds, at which svcmgr retries a restart that
/// waits for memory while memmgr's level reads below `CRITICAL`. A tuning
/// value that bounds no capacity: it is how late a create that would now
/// succeed is made, there being no event for memory coming free below
/// `CRITICAL`.
pub const MEMORY_RETRY_MS: u64 = 1000;

/// The timed retries of one memory wait after which the service is
/// permanently down: about a minute, at [`MEMORY_RETRY_MS`], of memory too
/// short for its create while the level reads below `CRITICAL`. Time at
/// `CRITICAL` takes no timed retry, so an episode oomd has yet to end does not
/// count. A tuning value.
pub const MEMORY_RETRY_LIMIT: u32 = 60;

/// Why a restart's create failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CreateFailure
{
    /// procmgr replied `OUT_OF_MEMORY`.
    OutOfMemory,
    /// Any other failure: a walk, a badge mint, a transport error, another
    /// procmgr refusal, a short reply, a step after the create.
    Other,
}

/// What woke svcmgr for its waiting restarts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Wake
{
    /// A signal of the pressure Notification: the level changed.
    Signal,
    /// The main loop's wait timed out after [`MEMORY_RETRY_MS`].
    Timer,
}

/// A retry of every waiting restart that a [`Wake`] makes due.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Retry
{
    /// Whether the timer made it; only a timed retry counts against
    /// [`MEMORY_RETRY_LIMIT`], since signals are bounded by the changes of
    /// level.
    pub timed: bool,
}

/// The restart whose create procmgr refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refused
{
    /// The restart of a death, just decided, with the death's exit reason.
    Decided
    {
        exit_reason: u64
    },
    /// A retry of a waiting restart.
    Retried
    {
        wait: MemoryWait, retry: Retry
    },
}

/// One waiting restart: the exit reason of the death it restarts and the
/// timed retries made of it so far.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MemoryWait
{
    /// The exit reason of the death whose restart waits.
    pub exit_reason: u64,
    /// The retries the timer made, each refused for want of memory.
    pub timed_retries: u32,
}

/// svcmgr's side of the memory wait: whether it has the pressure
/// Notification, and memmgr's level as it last read it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MemoryWaits
{
    registered: bool,
    level: Option<u64>,
}

impl MemoryWaits
{
    /// `registered` is whether svcmgr waits on the pressure Notification;
    /// without it no service waits. The level starts unread.
    #[must_use]
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`registered` is whether svcmgr has the Notification a wait needs"
    )]
    pub const fn new(registered: bool) -> Self
    {
        Self {
            registered,
            level: None,
        }
    }

    /// Record memmgr's level as svcmgr read it (`PRESSURE_*`), `None` when
    /// memmgr did not answer. svcmgr reads it after every refusal for want of
    /// memory and on every wake.
    pub fn record_level(&mut self, level: Option<u64>)
    {
        self.level = level;
    }

    /// The timeout of the main loop's wait, in milliseconds, `0` for none:
    /// [`MEMORY_RETRY_MS`] while a restart waits (`waiting`) and the level
    /// last read is below `CRITICAL`, and none otherwise, so svcmgr makes no
    /// idle wake-up.
    #[must_use]
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`waiting` is whether any restart waits for memory, which the timer needs"
    )]
    pub fn wait_timeout_ms(&self, waiting: bool) -> u64
    {
        if waiting && self.below_critical()
        {
            MEMORY_RETRY_MS
        }
        else
        {
            0
        }
    }

    /// The retry `wake` makes due, read against the level recorded on it:
    /// one below `CRITICAL`, none at `CRITICAL` (every such create is
    /// refused there, and memmgr signals the change) or unread.
    #[must_use]
    pub fn wake(&self, wake: Wake) -> Option<Retry>
    {
        self.below_critical().then_some(Retry {
            timed: wake == Wake::Timer,
        })
    }

    /// Where a refused create leaves the restart: `Some` the wait it is in,
    /// `None` down. `reserve_path` is whether the service never waits: a
    /// service created in the system reserve (`reserve = yes`), whose refusal
    /// means the reserve itself is spent, and the log sink, whose death's lines
    /// svcmgr holds until a next instance runs. Without the Notification no
    /// service waits.
    #[must_use]
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`reserve_path` is whether the service never waits, which the decision reads"
    )]
    pub fn on_refusal(
        &self,
        refused: Refused,
        failure: CreateFailure,
        reserve_path: bool,
    ) -> Option<MemoryWait>
    {
        if failure != CreateFailure::OutOfMemory || reserve_path || !self.registered
        {
            return None;
        }
        match refused
        {
            Refused::Decided { exit_reason } => Some(MemoryWait {
                exit_reason,
                timed_retries: 0,
            }),
            Refused::Retried { mut wait, retry } =>
            {
                if retry.timed
                {
                    wait.timed_retries = wait.timed_retries.saturating_add(1);
                }
                (wait.timed_retries < MEMORY_RETRY_LIMIT).then_some(wait)
            }
        }
    }

    /// Whether the level last read is below `CRITICAL`.
    fn below_critical(&self) -> bool
    {
        matches!(self.level, Some(level) if level != PRESSURE_CRITICAL)
    }
}

#[cfg(test)]
mod tests
{
    use ipc::memmgr_labels::{PRESSURE_CRITICAL, PRESSURE_LOW, PRESSURE_NORMAL};

    use super::CreateFailure::{Other, OutOfMemory};
    use super::{
        MEMORY_RETRY_LIMIT, MEMORY_RETRY_MS, MemoryWait, MemoryWaits, Refused, Retry, Wake,
    };
    use crate::DeathTag;
    use crate::death_tag::routes;

    const KILLED: u64 = 0x2000;
    const LEVELS: [Option<u64>; 4] = [
        None,
        Some(PRESSURE_CRITICAL),
        Some(PRESSURE_LOW),
        Some(PRESSURE_NORMAL),
    ];
    const SIGNAL: Retry = Retry { timed: false };
    const TIMER: Retry = Retry { timed: true };

    fn at(level: Option<u64>) -> MemoryWaits
    {
        let mut waits = MemoryWaits::new(true);
        waits.record_level(level);
        waits
    }

    fn waiting() -> MemoryWait
    {
        MemoryWait {
            exit_reason: KILLED,
            timed_retries: 0,
        }
    }

    // Decided -> waiting at every level: at CRITICAL, as when oomd stops a
    // service that is not the one holding the memory, and below it, for a
    // create larger than the margin above the growth floor.
    #[test]
    fn a_refusal_for_memory_waits_at_every_level()
    {
        for level in LEVELS
        {
            assert_eq!(
                at(level).on_refusal(
                    Refused::Decided {
                        exit_reason: KILLED
                    },
                    OutOfMemory,
                    false
                ),
                Some(waiting())
            );
        }
    }

    // Decided -> down.
    #[test]
    fn a_reserve_service_the_log_sink_and_every_other_failure_are_down()
    {
        for level in LEVELS
        {
            let refused = Refused::Decided {
                exit_reason: KILLED,
            };
            assert_eq!(at(level).on_refusal(refused, OutOfMemory, true), None);
            assert_eq!(at(level).on_refusal(refused, Other, false), None);
        }
    }

    #[test]
    fn without_the_notification_no_restart_waits()
    {
        let waits = MemoryWaits::new(false);
        let refused = Refused::Decided {
            exit_reason: KILLED,
        };
        assert_eq!(waits.on_refusal(refused, OutOfMemory, false), None);
    }

    // Waiting: a signal retries only once the level it leaves reads below
    // CRITICAL; a signal of a rise to CRITICAL, or an unread level, retries
    // nothing.
    #[test]
    fn a_signal_retries_only_below_critical()
    {
        assert_eq!(at(None).wake(Wake::Signal), None);
        assert_eq!(at(Some(PRESSURE_CRITICAL)).wake(Wake::Signal), None);
        assert_eq!(at(Some(PRESSURE_LOW)).wake(Wake::Signal), Some(SIGNAL));
        assert_eq!(at(Some(PRESSURE_NORMAL)).wake(Wake::Signal), Some(SIGNAL));
    }

    #[test]
    fn a_timer_tick_retries_only_below_critical()
    {
        assert_eq!(at(None).wake(Wake::Timer), None);
        assert_eq!(at(Some(PRESSURE_CRITICAL)).wake(Wake::Timer), None);
        assert_eq!(at(Some(PRESSURE_LOW)).wake(Wake::Timer), Some(TIMER));
        assert_eq!(at(Some(PRESSURE_NORMAL)).wake(Wake::Timer), Some(TIMER));
    }

    // No idle wake-up: the timer runs only while a restart waits and the level
    // reads below CRITICAL, since memory can come free there with no change
    // of level; at CRITICAL memmgr signals the change.
    #[test]
    fn the_timer_is_armed_only_while_a_restart_waits_below_critical()
    {
        for level in LEVELS
        {
            assert_eq!(at(level).wait_timeout_ms(false), 0);
        }
        assert_eq!(at(None).wait_timeout_ms(true), 0);
        assert_eq!(at(Some(PRESSURE_CRITICAL)).wait_timeout_ms(true), 0);
        assert_eq!(
            at(Some(PRESSURE_LOW)).wait_timeout_ms(true),
            MEMORY_RETRY_MS
        );
        assert_eq!(
            at(Some(PRESSURE_NORMAL)).wait_timeout_ms(true),
            MEMORY_RETRY_MS
        );
    }

    // The level moves the arming both ways: a fall below CRITICAL arms it, a
    // rise to CRITICAL disarms it.
    #[test]
    fn a_change_of_level_arms_and_disarms_the_timer()
    {
        let mut waits = at(Some(PRESSURE_CRITICAL));
        assert_eq!(waits.wait_timeout_ms(true), 0);
        waits.record_level(Some(PRESSURE_LOW));
        assert_eq!(waits.wait_timeout_ms(true), MEMORY_RETRY_MS);
        waits.record_level(Some(PRESSURE_CRITICAL));
        assert_eq!(waits.wait_timeout_ms(true), 0);
    }

    // Retry -> waiting: a retry on a signal refused for want of memory waits
    // again, uncounted; a timed one counts.
    #[test]
    fn a_refused_retry_waits_again()
    {
        let waits = at(Some(PRESSURE_LOW));
        let after_signal = waits.on_refusal(
            Refused::Retried {
                wait: waiting(),
                retry: SIGNAL,
            },
            OutOfMemory,
            false,
        );
        assert_eq!(after_signal, Some(waiting()));
        let after_timer = waits.on_refusal(
            Refused::Retried {
                wait: waiting(),
                retry: TIMER,
            },
            OutOfMemory,
            false,
        );
        assert_eq!(
            after_timer,
            Some(MemoryWait {
                exit_reason: KILLED,
                timed_retries: 1,
            })
        );
    }

    // Retry -> down: any other failure of a retry.
    #[test]
    fn a_retry_failing_otherwise_is_down()
    {
        let refused = Refused::Retried {
            wait: waiting(),
            retry: TIMER,
        };
        assert_eq!(
            at(Some(PRESSURE_LOW)).on_refusal(refused, Other, false),
            None
        );
    }

    // Retry -> down: the limit of timed retries ends a wait whose memory never
    // comes free, so a critical service still reaches the shutdown path;
    // signals alone never do.
    #[test]
    fn the_limit_of_timed_retries_ends_the_wait()
    {
        let waits = at(Some(PRESSURE_NORMAL));
        let mut wait = waiting();
        for _ in 0..1000
        {
            wait = waits
                .on_refusal(
                    Refused::Retried {
                        wait,
                        retry: SIGNAL,
                    },
                    OutOfMemory,
                    false,
                )
                .expect("a signal's retry is not counted");
        }
        for count in 1..MEMORY_RETRY_LIMIT
        {
            wait = waits
                .on_refusal(Refused::Retried { wait, retry: TIMER }, OutOfMemory, false)
                .expect("below the limit");
            assert_eq!(wait.timed_retries, count);
        }
        assert_eq!(
            waits.on_refusal(Refused::Retried { wait, retry: TIMER }, OutOfMemory, false),
            None
        );
        assert_eq!(wait.exit_reason, KILLED);
    }

    // Waiting: the entry is inactive with no instance, so a late death post
    // of its dead instance, or of any instance, is dropped; a new death can
    // come only from a retry's new instance, which reactivates the entry.
    // The same inactive entry is what the stop authority and the shutdown
    // path read as not running (svcmgr's `service_running`).
    #[test]
    fn no_death_routes_to_a_waiting_entry()
    {
        for instance in [0, 1, 7]
        {
            assert!(!routes(DeathTag { slot: 3, instance }, false, instance));
        }
    }
}
